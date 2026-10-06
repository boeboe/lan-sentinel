#!/usr/bin/env bash
# Installs LAN Sentinel on a fresh Debian with systemd as PID 1 (a
# privileged container) exactly as deploy/README.md says: the files of a
# release tarball, then its "2. Install" block run verbatim. `make
# test-systemd` first builds the binaries into BIN_DIR in the dev container.
# It runs once per target Debian release (RELEASES, default: the targets
# bullseye, bookworm and trixie, systemd 247, 252 and 257).
# Checks Type=notify start-up, the service identity and capabilities, the
# clock sync state, the database, SIGHUP and `config reload`, an upgrade with
# the same install commands, clean shutdown and the
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
# The board audit, the block after "## On a target board".
audit_block=$(awk '/^## On a target board/ { f = 1; next } f && /^```bash/ { p = 1; next } p && /^```/ { exit } p' tools/capcheck/README.md)
[ -n "$audit_block" ] || { echo "test-systemd: no board audit block in tools/capcheck/README.md" >&2; exit 2; }

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
journal_count() { x journalctl -u lan-sentinel --no-pager -o cat | grep -c "$1" || true; }
journal_more() { [ "$(journal_count "$1")" -gt "$2" ]; } # journal_more TEXT N: more than N lines with TEXT
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

# config reload as an operator runs it: one change applies, one needs a
# restart, and an invalid file changes nothing (exit 2).
exits() { # exits CODE COMMAND...
	local want=$1
	shift
	"$@" >/dev/null 2>&1
	[ $? = "$want" ]
}
x sed -i 's/level: info/level: debug/; s/promiscuous: false/promiscuous: true/' /etc/lan-sentinel/config.yaml
x sudo lan-sentinel config reload >"$work/reload.txt" 2>&1 || true
check "config reload applies the log level" grep -Eq '^  logging\.level +info +debug$' "$work/reload.txt"
check "config reload lists a restart-only change" grep -Eq '^  interfaces\[0\]\.passive\.promiscuous +false +true$' "$work/reload.txt"
x sed -i 's/level: debug/level: loud/' /etc/lan-sentinel/config.yaml
check "config reload rejects an invalid file" exits 2 x sudo lan-sentinel config reload
check "the rejection is logged" journal_has "configuration reload rejected"
x sed -i 's/level: loud/level: info/; s/promiscuous: true/promiscuous: false/' /etc/lan-sentinel/config.yaml
if [ "$fail" != 0 ] || [ -n "${KEEP_JOURNAL:-}" ]; then cat "$work/reload.txt"; fi

score=$(x systemd-analyze security lan-sentinel --no-pager 2>/dev/null | grep 'Overall exposure level' | grep -oE '[0-9]+\.[0-9]+' || true)
check "systemd-analyze security exposure ${score:-unknown} <= 2.5 (NFR-SEC-1)" awk -v s="${score:-99}" 'BEGIN { exit !(s <= 2.5) }'
if [ -n "${KEEP_JOURNAL:-}" ]; then x journalctl -u lan-sentinel --no-pager -o short-monotonic; fi

gw_hex=$(x awk '$2 == "00000000" { print $3; exit }' /proc/net/route)
gw=$(printf '%d.%d.%d.%d' "0x${gw_hex:6:2}" "0x${gw_hex:4:2}" "0x${gw_hex:2:2}" "0x${gw_hex:0:2}")
# The board audit of tools/capcheck/README.md, run as written there but on
# the container's gateway, without a terminal, and with a short capture.
audit=$(printf '%s\n' "$audit_block" | sed -e 's/--pty/--pipe --quiet/' -e "s/192\.168\.0\.1/$gw/g" -e 's|/usr/local/bin/capcheck |&--capture 2s |')
echo "info: capcheck under the unit sandbox, as in tools/capcheck/README.md, targets $gw"
if docker exec -w /root/release "$NAME" bash -euo pipefail -c "$audit" >"$work/capcheck.txt" 2>&1; then
	echo "ok:   capcheck passes under the installed unit's sandbox"
else
	echo "FAIL: capcheck under the installed unit's sandbox" >&2
	fail=1
fi
check "capcheck sees root with CAP_NET_RAW only" grep -Eq '^privilege: +CapEff=0x2000: euid 0 \(root\), CAP_NET_RAW$' "$work/capcheck.txt"
if [ "$fail" != 0 ] || [ -n "${KEEP_JOURNAL:-}" ]; then cat "$work/capcheck.txt"; fi

# The same commands again, as an upgrade over the running daemon: they keep
# the site's config and restart the daemon on the installed binary.
x sh -c 'echo "# site edit, kept across upgrades" >>/etc/lan-sentinel/config.yaml'
before=$(x systemctl show -p MainPID --value lan-sentinel)
stops=$(journal_count "lan-sentinel stopped")
if docker exec -w /root/release "$NAME" bash -euxo pipefail -c "$install_block" >"$work/upgrade.txt" 2>&1; then
	echo "ok:   the install commands run again over the running daemon"
else
	echo "FAIL: the install commands run again over the running daemon" >&2
	cat "$work/upgrade.txt" >&2
	fail=1
fi
restarted() {
	local now
	now=$(x systemctl show -p MainPID --value lan-sentinel)
	[ "$now" != 0 ] && [ "$now" != "$before" ]
}
check "the upgrade keeps the site's config" x grep -q "site edit, kept across upgrades" /etc/lan-sentinel/config.yaml
check "the upgrade restarts the daemon" wait_for 60 restarted
check "service active after the upgrade" wait_for 60 x systemctl is-active --quiet lan-sentinel
check "the upgrade stopped the previous daemon cleanly" journal_more "lan-sentinel stopped" "$stops"

stops=$(journal_count "lan-sentinel stopped")
x systemctl stop lan-sentinel
check "clean shutdown" wait_for 15 journal_more "lan-sentinel stopped" "$stops"
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
