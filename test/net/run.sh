#!/usr/bin/env bash
# Network integration tests in Docker (docs/ARCHITECTURE.md §9): `make
# test-net`, which first builds the binaries into BIN_DIR in the dev container
# (build/test-bins.sh).
#
# A bridge network with fixed subnets stands in for an OT LAN. Simulated hosts
# are busybox containers with fixed MACs. The test binaries run in a runner
# container as uid 65534 with only CAP_NET_RAW (ambient), stricter than the
# systemd unit (root with a CAP_NET_RAW bounding set). Go tests can ask for changes outside the runner (swap the host
# behind an IP, stop a host, connect a second network, inject frames from
# other MACs) through request files in a shared directory; the loop below
# performs them.
set -euo pipefail
cd "$(dirname "$0")/../.."

NET=lan-sentinel-test NET2=lan-sentinel-test2
SUBNET4=172.31.250.0/24 GW4=172.31.250.1 SUBNET6=fd5e:5e:1::/64
SUBNET2=172.31.251.0/24 GW2=172.31.251.1 RUNNER_IP2=172.31.251.2
RUNNER=ls-runner RUNNER_IP=172.31.250.2
OPEN_IP=172.31.250.10 OPEN_IP6=fd5e:5e:1::10 OPEN_MAC=02:00:00:00:fa:0a # TCP listener on 502
CLOSED_IP=172.31.250.11 CLOSED_MAC=02:00:00:00:fa:0b                   # no listener: REFUSED
SWAP_IP=172.31.250.12 SWAP_MAC_A=02:00:00:00:fa:a1 SWAP_MAC_B=02:00:00:00:fa:b1 # host swapped on request
GONE_IP=172.31.250.13 GONE_MAC=02:00:00:00:fa:0d                       # host stopped on request
PLC_IP=172.31.250.14 PLC_MAC=00:1b:1b:00:fa:0e                         # real OUI (Siemens AG): vendor lookup
VANISH_IP=172.31.250.130 VANISH_MAC=02:00:00:00:fa:82                  # known to active discovery, then stopped: UNREACHABLE
TWIN_IP=172.31.251.10                                                  # on NET2, same MAC as OPEN: per-interface scoping
ABSENT_IP=172.31.250.99                                                # nobody: TIMEOUT / FAILED
RUNNER_IMAGE=${RUNNER_IMAGE:-debian:bookworm-slim}
HOST_IMAGE=${HOST_IMAGE:-busybox:stable}
BIN_DIR=$(cd "${BIN_DIR:-.build/test}" && pwd)
HOSTS=(ls-open ls-closed ls-swap-a ls-swap-b ls-gone ls-plc ls-twin ls-vanish)

work=$(mktemp -d)
cleanup_docker() {
	docker rm -f "$RUNNER" "${HOSTS[@]}" >/dev/null 2>&1 || true
	docker network rm "$NET" "$NET2" >/dev/null 2>&1 || true
}
cleanup() {
	cleanup_docker
	rm -rf "$work"
}
trap cleanup EXIT

if ! docker info >/dev/null 2>&1; then
	echo "test-net: Docker is not running" >&2
	exit 2
fi
for b in capcheck inject; do
	[ -x "$BIN_DIR/$b" ] || { echo "test-net: $BIN_DIR/$b missing; run via make test-net" >&2; exit 2; }
done
# The runner executes the binaries as uid 65534 and writes request files as
# that uid, so set the permissions it needs explicitly: mktemp creates a 0700
# directory, and on a Linux Docker host (CI) bind mounts keep host
# permissions. Docker Desktop does not enforce them, which hides the problem.
mkdir -p "$work/t" "$work/sync"
cp "$BIN_DIR"/capcheck "$BIN_DIR"/inject "$work/t/"
tests=()
for t in "$BIN_DIR"/*.test; do
	[ -e "$t" ] || continue
	cp "$t" "$work/t/"
	tests+=("$(basename "$t")")
done
chmod 0755 "$work" "$work/t" "$work"/t/*
chmod 1777 "$work/sync"

echo "== networks $NET ($SUBNET4, $SUBNET6) and $NET2 ($SUBNET2)"
cleanup_docker
ipv6=1
if ! docker network create --driver bridge --subnet "$SUBNET4" --gateway "$GW4" --ipv6 --subnet "$SUBNET6" "$NET" >/dev/null 2>&1; then
	echo "   (IPv6 networks unavailable; NDP checks will be skipped)"
	ipv6=0
	docker network create --driver bridge --subnet "$SUBNET4" --gateway "$GW4" "$NET" >/dev/null
fi
docker network create --driver bridge --subnet "$SUBNET2" --gateway "$GW2" "$NET2" >/dev/null
open_ip6=()
[ "$ipv6" = 1 ] && open_ip6=(--ip6 "$OPEN_IP6")
host() { # host NAME IP MAC CMD... (on NET; set HOST_NET for another network)
	local name=$1 ip=$2 mac=$3
	shift 3
	docker run -d --name "$name" --network "${HOST_NET:-$NET}" --ip "$ip" --mac-address "$mac" "$@" >/dev/null
}
# ${arr[@]+"${arr[@]}"}: an empty array is unset to bash 3.2 (macOS) under set -u.
host ls-open "$OPEN_IP" "$OPEN_MAC" ${open_ip6[@]+"${open_ip6[@]}"} "$HOST_IMAGE" httpd -f -p 502 -h /tmp
host ls-closed "$CLOSED_IP" "$CLOSED_MAC" "$HOST_IMAGE" sleep 3600
host ls-swap-a "$SWAP_IP" "$SWAP_MAC_A" "$HOST_IMAGE" sleep 3600
host ls-gone "$GONE_IP" "$GONE_MAC" "$HOST_IMAGE" sleep 3600
host ls-plc "$PLC_IP" "$PLC_MAC" "$HOST_IMAGE" sleep 3600
host ls-vanish "$VANISH_IP" "$VANISH_MAC" "$HOST_IMAGE" sleep 3600
HOST_NET=$NET2 host ls-twin "$TWIN_IP" "$OPEN_MAC" "$HOST_IMAGE" sleep 3600

# runner CAPS ARGS... runs ARGS as uid 65534 with exactly the ambient
# capabilities in CAPS (e.g. "+net_raw" or "" for none). RUNNER_EXTRA holds
# further docker run options.
RUNNER_EXTRA=()
runner() {
	local caps=$1
	shift
	docker run --rm --name "$RUNNER" --network "$NET" --ip "$RUNNER_IP" -v "$work/t:/t:ro" -v "$work/sync:/sync" \
		${RUNNER_EXTRA[@]+"${RUNNER_EXTRA[@]}"} \
		-e LS_TEST_IFACE=eth0 -e LS_TEST_SYNC=/sync -e LS_TEST_IPV6="$ipv6" \
		-e LS_TEST_OPEN="$OPEN_IP:502" -e LS_TEST_OPEN_MAC="$OPEN_MAC" \
		-e LS_TEST_CLOSED="$CLOSED_IP:502" -e LS_TEST_CLOSED_MAC="$CLOSED_MAC" \
		-e LS_TEST_SWAP="$SWAP_IP" -e LS_TEST_SWAP_MAC_A="$SWAP_MAC_A" -e LS_TEST_SWAP_MAC_B="$SWAP_MAC_B" \
		-e LS_TEST_GONE="$GONE_IP" -e LS_TEST_GONE_MAC="$GONE_MAC" -e LS_TEST_ABSENT="$ABSENT_IP" \
		-e LS_TEST_PLC="$PLC_IP" -e LS_TEST_PLC_MAC="$PLC_MAC" -e LS_TEST_TWIN="$TWIN_IP" \
		-e LS_TEST_NET2_PREFIX="$SUBNET2" -e LS_TEST_PREFIX="$SUBNET4" \
		-e LS_TEST_VANISH="$VANISH_IP" -e LS_TEST_VANISH_MAC="$VANISH_MAC" \
		--cap-drop ALL --cap-add NET_RAW --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
		"$RUNNER_IMAGE" setpriv --reuid=65534 --regid=65534 --clear-groups \
		--bounding-set="-all${caps:+,$caps}" --inh-caps="-all${caps:+,$caps}" --ambient-caps="-all${caps:+,$caps}" \
		"$@"
}

# act ACTION [ARGS...] performs one requested change outside the runner.
act() {
	case $1 in
	inject) # send the frames of a pcap file the test wrote into the sync directory, from another container
		docker run --rm --network "$NET" -v "$work/t:/t:ro" -v "$work/sync:/sync:ro" "$RUNNER_IMAGE" \
			/t/inject -i eth0 -f "/sync/$2" -repeat "${3:-1}" ;;
	swap) # replace the host behind SWAP_IP by one with another MAC, which announces itself
		docker rm -f ls-swap-a >/dev/null
		host ls-swap-b "$SWAP_IP" "$SWAP_MAC_B" "$HOST_IMAGE" sh -c "arping -U -c 3 -I eth0 $SWAP_IP; sleep 3600" ;;
	stop-gone) docker rm -f ls-gone >/dev/null ;;
	stop-vanish) docker rm -f ls-vanish >/dev/null ;;
	net-connect) docker network connect --ip "$RUNNER_IP2" "$NET2" "$RUNNER" ;;
	down-iface-add) # an administratively down interface in the runner's namespace (needs CAP_NET_ADMIN there, not in the runner)
		docker run --rm --network "container:$RUNNER" --cap-add NET_ADMIN "$HOST_IMAGE" ip link add "$2" type dummy ;;
	down-iface-up) docker run --rm --network "container:$RUNNER" --cap-add NET_ADMIN "$HOST_IMAGE" ip link set "$2" up ;;
	down-iface-del) docker run --rm --network "container:$RUNNER" --cap-add NET_ADMIN "$HOST_IMAGE" ip link del "$2" ;;
	net-disconnect) docker network disconnect "$NET2" "$RUNNER" ;;
	*) echo "test-net: unknown action $1" >&2; return 1 ;;
	esac
}

# serve_requests PID performs requested actions until PID exits. A request
# is <action>@<id>.request holding the action's arguments; the reply is
# <action>@<id>.done (or .failed), so repeating an action never matches an
# earlier reply.
serve_requests() {
	local pid=$1 req name action args
	while kill -0 "$pid" 2>/dev/null; do
		for req in "$work"/sync/*.request; do
			[ -e "$req" ] || continue
			name=$(basename "$req" .request)
			action=${name%@*}
			args=()
			read -r -a args <"$req" || true
			rm -f "$req"
			# ${args[@]+...}: an empty array is unset to bash 3.2 (macOS) under set -u.
			echo "   action: $action ${args[*]+${args[*]}}"
			if act "$action" ${args[@]+"${args[@]}"}; then touch "$work/sync/$name.done"; else touch "$work/sync/$name.failed"; fi
		done
		sleep 0.2
	done
}

fail=0
ndp=()
[ "$ipv6" = 1 ] && ndp=(--ndp-target "$OPEN_IP6")
capcheck=(/t/capcheck --interface eth0 --capture 3s --arp-target "$OPEN_IP" ${ndp[@]+"${ndp[@]}"} --icmp-target "$OPEN_IP" --tcp-target "$OPEN_IP:502")

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

for bin in ${tests[@]+"${tests[@]}"}; do
	echo "== $bin"
	runner +net_raw "/t/$bin" -test.v -test.timeout 5m &
	pid=$!
	serve_requests "$pid"
	wait "$pid" || fail=1
done

# Where net.ipv4.ping_group_range excludes the daemon's group (common on
# boards), ICMP falls back to a raw socket under CAP_NET_RAW.
RUNNER_EXTRA=(--sysctl "net.ipv4.ping_group_range=1 0" -e LS_TEST_RAW_ICMP=1)
for bin in ${tests[@]+"${tests[@]}"}; do
	echo "== $bin (ping sockets not allowed)"
	runner +net_raw "/t/$bin" -test.v -test.timeout 2m -test.run '^TestICMPRawSocket$' || fail=1
done
RUNNER_EXTRA=()

if [ "$fail" = 0 ]; then
	echo "== test-net: PASS"
else
	echo "== test-net: FAIL" >&2
fi
exit "$fail"
