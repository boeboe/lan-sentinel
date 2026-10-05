#!/usr/bin/env bash
# Network integration tests in Docker (docs/ARCHITECTURE.md §9): `make
# test-net`, which first builds the binaries into BIN_DIR in the dev container
# (build/test-bins.sh).
#
# A bridge network with fixed subnets stands in for an OT LAN. Simulated hosts
# are busybox containers. The test binaries run in a runner container as uid
# 65534 with only CAP_NET_RAW (ambient), mirroring the systemd unit.
set -euo pipefail
cd "$(dirname "$0")/../.."

NET=lan-sentinel-test
SUBNET4=172.31.250.0/24 GW4=172.31.250.1
SUBNET6=fd5e:5e:1::/64
RUNNER_IP=172.31.250.2
OPEN_IP=172.31.250.10 OPEN_IP6=fd5e:5e:1::10   # TCP listener on 502
CLOSED_IP=172.31.250.11                        # no listener: REFUSED
ABSENT_IP=172.31.250.99                        # nobody: TIMEOUT
RUNNER_IMAGE=${RUNNER_IMAGE:-debian:bookworm-slim}
HOST_IMAGE=${HOST_IMAGE:-busybox:stable}
BIN_DIR=$(cd "${BIN_DIR:-.build/test}" && pwd)

work=$(mktemp -d)
cleanup() {
	docker rm -f ls-open ls-closed >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

if ! docker info >/dev/null 2>&1; then
	echo "test-net: Docker is not running" >&2
	exit 2
fi
[ -x "$BIN_DIR/capcheck" ] || { echo "test-net: $BIN_DIR/capcheck missing; run via make test-net" >&2; exit 2; }
cp "$BIN_DIR"/capcheck "$work/"
tests=()
for t in "$BIN_DIR"/*.test; do
	[ -e "$t" ] || continue
	cp "$t" "$work/"
	tests+=("$(basename "$t")")
done

echo "== network $NET ($SUBNET4, $SUBNET6)"
cleanup_net_only() { docker rm -f ls-open ls-closed >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
cleanup_net_only
ipv6=1
if ! docker network create --driver bridge --subnet "$SUBNET4" --gateway "$GW4" --ipv6 --subnet "$SUBNET6" "$NET" >/dev/null 2>&1; then
	echo "   (IPv6 networks unavailable; NDP checks will be skipped)"
	ipv6=0
	docker network create --driver bridge --subnet "$SUBNET4" --gateway "$GW4" "$NET" >/dev/null
fi
open_ip6=()
[ "$ipv6" = 1 ] && open_ip6=(--ip6 "$OPEN_IP6")
docker run -d --name ls-open --network "$NET" --ip "$OPEN_IP" "${open_ip6[@]}" "$HOST_IMAGE" httpd -f -p 502 -h /tmp >/dev/null
docker run -d --name ls-closed --network "$NET" --ip "$CLOSED_IP" "$HOST_IMAGE" sleep 3600 >/dev/null

# runner CAPS ARGS... runs ARGS as uid 65534 with exactly the ambient
# capabilities in CAPS (e.g. "+net_raw" or "" for none).
runner() {
	local caps=$1
	shift
	docker run --rm --network "$NET" --ip "$RUNNER_IP" -v "$work:/t:ro" \
		-e LS_TEST_IFACE=eth0 -e LS_TEST_OPEN="$OPEN_IP:502" -e LS_TEST_CLOSED="$CLOSED_IP:502" \
		-e LS_TEST_ABSENT="$ABSENT_IP" -e LS_TEST_IPV6="$ipv6" \
		--cap-drop ALL --cap-add NET_RAW --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
		"$RUNNER_IMAGE" setpriv --reuid=65534 --regid=65534 --clear-groups \
		--bounding-set="-all${caps:+,$caps}" --inh-caps="-all${caps:+,$caps}" --ambient-caps="-all${caps:+,$caps}" \
		"$@"
}

fail=0
ndp=()
[ "$ipv6" = 1 ] && ndp=(--ndp-target "$OPEN_IP6")
capcheck=(/t/capcheck --interface eth0 --capture 3s --arp-target "$OPEN_IP" "${ndp[@]}" --icmp-target "$OPEN_IP" --tcp-target "$OPEN_IP:502")

echo "== capcheck as uid 65534 with only CAP_NET_RAW (expect every check to pass)"
if ! runner +net_raw "${capcheck[@]}" | tee "$work/with-caps.txt"; then
	echo "FAIL: capcheck reported failures with CAP_NET_RAW" >&2
	fail=1
fi
if ! grep -Eq '^privilege: +CapEff=0x2000: CAP_NET_RAW$' "$work/with-caps.txt"; then
	echo "FAIL: runner did not have exactly CAP_NET_RAW" >&2
	fail=1
fi

echo "== capcheck as uid 65534 without capabilities (expect AF_PACKET to fail)"
if runner "" "${capcheck[@]}" >"$work/no-caps.txt"; then
	echo "FAIL: capcheck passed without CAP_NET_RAW; the check does not discriminate" >&2
	fail=1
elif ! grep -Eq '^AF_PACKET socket bound to interface +FAIL' "$work/no-caps.txt"; then
	echo "FAIL: AF_PACKET did not fail without CAP_NET_RAW" >&2
	cat "$work/no-caps.txt" >&2
	fail=1
else
	echo "ok: AF_PACKET refused without CAP_NET_RAW"
fi

for bin in "${tests[@]}"; do
	echo "== $bin"
	runner +net_raw "/t/$bin" -test.v || fail=1
done

if [ "$fail" = 0 ]; then
	echo "== test-net: PASS"
else
	echo "== test-net: FAIL" >&2
fi
exit "$fail"
