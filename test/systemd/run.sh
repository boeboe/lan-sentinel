#!/usr/bin/env bash
# Installs LAN Sentinel on a fresh Debian with systemd as PID 1 (a
# privileged container) exactly as deploy/README.md says: the files of a
# release tarball, then its "2. Install" block run verbatim. `make
# test-systemd` first builds the binaries into BIN_DIR in the dev container.
# It runs once per target Debian release (RELEASES, default: the targets
# bullseye, bookworm and trixie, systemd 247, 252 and 257).
# Checks Type=notify start-up, the service identity and capabilities, the
# clock sync state, the database, SIGHUP reload, clean shutdown and the
# systemd-analyze score, and runs tools/capcheck as a transient unit with
# exactly the reference unit's [Service] sandboxing and capabilities.
set -euo pipefail
cd "$(dirname "$0")/../.."
NAME=lan-sentinel-systemd
BIN_DIR=${BIN_DIR:-.build/test}
RELEASES=${RELEASES:-bullseye bookworm trixie}
work=$(mktemp -d)
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT

docker info >/dev/null 2>&1 || { echo "test-systemd: Docker is not running" >&2; exit 2; }
for b in lan-sentinel capcheck; do
	[ -x "$BIN_DIR/$b" ] || { echo "test-systemd: $BIN_DIR/$b missing; run via make test-systemd" >&2; exit 2; }
	cp "$BIN_DIR/$b" "$work/"
done
cp deploy/lan-sentinel.service deploy/config.yaml deploy/README.md "$work/"
# The install commands of the runbook, the block after "### 2. Install".
install_block=$(awk '/^### 2\. Install/ { f = 1; next } f && /^```bash/ { p = 1; next } p && /^```/ { exit } p' deploy/README.md)
[ -n "$install_block" ] || { echo "test-systemd: no install block in deploy/README.md" >&2; exit 2; }

x() { docker exec "$NAME" "$@"; }
total=0
summary=()

# run_on RELEASE runs every check under that Debian release's systemd.
run_on() {
local release=$1 image=lan-sentinel-systemd-test:$1
echo "== Debian $release"
docker build -q --build-arg "BASE=debian:$release-slim" -t "$image" -f test/systemd/Dockerfile test/systemd >/dev/null
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
	--tmpfs /run --tmpfs /run/lock "$image" >/dev/null
fail=0
echo "info: $(x systemctl --version | head -1)"
# The release tarball's directory (as build/release.sh package lays it out).
x mkdir -p /root/release
for f in "$work"/*; do docker cp "$f" "$NAME:/root/release/" >/dev/null; done
x sh -c 'cd /root/release && sha256sum lan-sentinel capcheck >SHA256SUMS'
for _ in $(seq 1 30); do # until systemd has booted (running, or degraded in a container)
	case $(x systemctl is-system-running --wait 2>/dev/null) in running | degraded) break ;; esac
	sleep 1
done
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

if docker exec -w /root/release "$NAME" bash -euxo pipefail -c "$install_block" >"$work/install.txt" 2>&1; then
	echo "ok:   install with the commands of deploy/README.md"
else
	echo "FAIL: install with the commands of deploy/README.md" >&2
	cat "$work/install.txt" >&2
	fail=1
fi
check "service active (Type=notify readiness)" wait_for 60 x systemctl is-active --quiet lan-sentinel
pid=$(x systemctl show -p MainPID --value lan-sentinel)
status=$(x cat "/proc/$pid/status")
check "runs as root" grep -Eq "^Uid:\s+0\s" <<<"$status"
check "effective capabilities are CAP_NET_RAW only" grep -Eq '^CapEff:\s+0000000000002000$' <<<"$status"
check "bounding set is CAP_NET_RAW only" grep -Eq '^CapBnd:\s+0000000000002000$' <<<"$status"
check "database created in /data/lan-sentinel" x test -f /data/lan-sentinel/hosts.db
check "events go to the journal" journal_has "lan-sentinel running"
check "passive capture runs under the unit (AF_PACKET)" wait_for 10 journal_has "capture started"
check "no capture failures" bash -c "! docker exec $NAME journalctl -u lan-sentinel --no-pager -o cat | grep -q 'capture unavailable'"
check "API socket is 0660 root:root" bash -c "[ \"\$(docker exec $NAME stat -c '%a %U %G' /run/lan-sentinel/api.sock)\" = '660 root root' ]"
check "daemon status over the API socket (healthy)" x lan-sentinel daemon status --quiet
clock=$(x lan-sentinel daemon status -o json | grep -oE '"clock": *"[a-z]+"' | grep -oE '[a-z]+"$' | tr -d '"')
check "clock sync state readable under the unit (${clock:-none}, not unknown)" bash -c "[ '$clock' = synced ] || [ '$clock' = unsynced ]"
check "hosts list over the API" x lan-sentinel hosts list
check "offline read beside the running daemon" x lan-sentinel --offline db check

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
# capcheck is not installed (the board audit runs it from the unpacked
# release); the sandbox hides /root, so put it where the unit can see it.
x install -m 0755 /root/release/capcheck /usr/local/bin/capcheck
echo "info: capcheck under the unit sandbox ($((${#props[@]} / 2)) settings), ARP/ICMP target $gw"
# A unit file only warns about a setting its systemd does not know (e.g.
# PrivateIPC= before systemd 248) and runs without it; a transient unit
# refuses it, so leave such settings out the same way.
passed=0
for _ in 1 2 3 4 5; do
	if x systemd-run --quiet --wait --pipe --collect "${props[@]}" \
		/usr/local/bin/capcheck --interface eth0 --capture 2s --arp-target "$gw" --icmp-target "$gw" >"$work/capcheck.txt" 2>&1; then
		passed=1
		break
	fi
	unknown=$(sed -nE 's/.*Unknown assignment: ([A-Za-z]+)=.*/\1/p' "$work/capcheck.txt" | head -1)
	[ -n "$unknown" ] || break
	echo "info: this systemd does not know $unknown= (the unit runs without it too); capcheck runs without it"
	kept=()
	for ((i = 0; i < ${#props[@]}; i += 2)); do
		[[ ${props[$((i + 1))]} == "$unknown="* ]] || kept+=("${props[$i]}" "${props[$((i + 1))]}")
	done
	props=("${kept[@]}")
done
if [ "$passed" = 1 ]; then
	echo "ok:   capcheck passes under the reference unit's sandbox"
else
	echo "FAIL: capcheck under the reference unit's sandbox" >&2
	fail=1
fi
check "capcheck sees root with CAP_NET_RAW only" grep -Eq '^privilege: +CapEff=0x2000: euid 0 \(root\), CAP_NET_RAW$' "$work/capcheck.txt"
if [ "$fail" != 0 ] || [ -n "${KEEP_JOURNAL:-}" ]; then cat "$work/capcheck.txt"; fi

x systemctl stop lan-sentinel
check "clean shutdown" wait_for 15 journal_has "lan-sentinel stopped"
check "WAL and -shm removed on shutdown (after API traffic)" x sh -c '! test -e /data/lan-sentinel/hosts.db-wal && ! test -e /data/lan-sentinel/hosts.db-shm'

summary+=("Debian $release: $(x systemctl --version | head -1 | cut -d' ' -f1-2), exposure ${score:-unknown}, clock ${clock:-unknown}: $([ "$fail" = 0 ] && echo PASS || echo FAIL)")
if [ "$fail" != 0 ]; then
	echo "--- journal" >&2
	x journalctl -u lan-sentinel --no-pager >&2 || true
	total=1
fi
docker rm -f "$NAME" >/dev/null 2>&1 || true
}

for r in $RELEASES; do
	run_on "$r"
done
printf '%s\n' "${summary[@]}"
if [ "$total" != 0 ]; then
	echo "== test-systemd: FAIL" >&2
	exit 1
fi
echo "== test-systemd: PASS"
