#!/usr/bin/env bash
# Runs the daemon under systemd in a privileged container with the reference
# unit, sysusers.d and tmpfiles.d files from deploy/: `make test-systemd`,
# which first builds the binaries into BIN_DIR in the dev container.
# Checks Type=notify start-up, the service identity and capabilities, the
# database, SIGHUP reload, clean shutdown and the systemd-analyze score, and
# runs tools/capcheck as a transient unit with exactly the reference unit's
# [Service] sandboxing and capabilities.
set -euo pipefail
cd "$(dirname "$0")/../.."
IMAGE=lan-sentinel-systemd-test
NAME=lan-sentinel-systemd
BIN_DIR=${BIN_DIR:-.build/test}
work=$(mktemp -d)
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT

docker info >/dev/null 2>&1 || { echo "test-systemd: Docker is not running" >&2; exit 2; }
for b in lan-sentinel capcheck; do
	[ -x "$BIN_DIR/$b" ] || { echo "test-systemd: $BIN_DIR/$b missing; run via make test-systemd" >&2; exit 2; }
	cp "$BIN_DIR/$b" "$work/"
done
cp deploy/lan-sentinel.service deploy/lan-sentinel.sysusers deploy/lan-sentinel.tmpfiles test/systemd/config.yaml "$work/"
docker build -q -t "$IMAGE" -f test/systemd/Dockerfile "$work" >/dev/null
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
	--tmpfs /run --tmpfs /run/lock "$IMAGE" >/dev/null

x() { docker exec "$NAME" "$@"; }
fail=0
check() { # check DESCRIPTION COMMAND...
	local d=$1
	shift
	if "$@"; then echo "ok:   $d"; else echo "FAIL: $d" >&2; fail=1; fi
}
journal_has() { x journalctl -u lan-sentinel --no-pager -o cat | grep -q "$1"; }
wait_for() { # wait_for SECONDS COMMAND...
	local n=$1
	shift
	for _ in $(seq 1 "$n"); do "$@" && return 0; sleep 1; done
	return 1
}

check "service active (Type=notify readiness)" wait_for 60 x systemctl is-active --quiet lan-sentinel
pid=$(x systemctl show -p MainPID --value lan-sentinel)
status=$(x cat "/proc/$pid/status")
check "runs as user lan-sentinel" grep -Eq "^Uid:\s+$(x id -u lan-sentinel)\s" <<<"$status"
check "effective capabilities are CAP_NET_RAW only" grep -Eq '^CapEff:\s+0000000000002000$' <<<"$status"
check "bounding set is CAP_NET_RAW only" grep -Eq '^CapBnd:\s+0000000000002000$' <<<"$status"
check "database created in /data/lan-sentinel" x test -f /data/lan-sentinel/hosts.db
check "events go to the journal" journal_has "lan-sentinel running"

x systemctl reload lan-sentinel
check "SIGHUP reload" wait_for 10 journal_has "configuration reloaded"
check "still active after reload" x systemctl is-active --quiet lan-sentinel

score=$(x systemd-analyze security lan-sentinel --no-pager 2>/dev/null | grep 'Overall exposure level' | grep -oE '[0-9]+\.[0-9]+' || true)
check "systemd-analyze security exposure ${score:-unknown} <= 2.5 (NFR-SEC-1)" awk -v s="${score:-99}" 'BEGIN { exit !(s <= 2.5) }'
if [ -n "${KEEP_JOURNAL:-}" ]; then x journalctl -u lan-sentinel --no-pager -o short-monotonic; fi

# capcheck under the unit's own sandbox: every [Service] setting except the
# ones that describe the daemon process itself.
props=()
while IFS= read -r line; do
	props+=(-p "$line")
done < <(x systemctl cat lan-sentinel.service | awk '
	/^\[/ { svc = ($0 == "[Service]"); next }
	svc && /^[A-Za-z]/ && $0 !~ /^(Type|ExecStart|ExecReload|WatchdogSec|Restart|RuntimeDirectory|RuntimeDirectoryMode)=/')
gw_hex=$(x awk '$2 == "00000000" { print $3; exit }' /proc/net/route)
gw=$(printf '%d.%d.%d.%d' "0x${gw_hex:6:2}" "0x${gw_hex:4:2}" "0x${gw_hex:2:2}" "0x${gw_hex:0:2}")
echo "info: capcheck under the unit sandbox ($((${#props[@]} / 2)) settings), ARP/ICMP target $gw"
if x systemd-run --quiet --wait --pipe --collect "${props[@]}" \
	/usr/local/bin/capcheck --interface eth0 --capture 2s --arp-target "$gw" --icmp-target "$gw" >"$work/capcheck.txt" 2>&1; then
	echo "ok:   capcheck passes under the reference unit's sandbox"
else
	echo "FAIL: capcheck under the reference unit's sandbox" >&2
	fail=1
fi
check "capcheck sees CAP_NET_RAW only" grep -Eq '^privilege: +CapEff=0x2000: CAP_NET_RAW$' "$work/capcheck.txt"
if [ "$fail" != 0 ] || [ -n "${KEEP_JOURNAL:-}" ]; then cat "$work/capcheck.txt"; fi

x systemctl stop lan-sentinel
check "clean shutdown" wait_for 15 journal_has "lan-sentinel stopped"
check "WAL removed on shutdown" x sh -c '! test -s /data/lan-sentinel/hosts.db-wal'

if [ "$fail" != 0 ]; then
	echo "--- journal" >&2
	x journalctl -u lan-sentinel --no-pager >&2 || true
	echo "== test-systemd: FAIL" >&2
	exit 1
fi
echo "== test-systemd: PASS"
