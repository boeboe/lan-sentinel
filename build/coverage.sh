#!/bin/bash
# Unit and golden tests with the race detector, measuring coverage of the
# daemon code (internal/...) exercised by every test package (-coverpkg).
# tools/ (exercised end to end by test-net and test-systemd), cmd/ (main)
# and the OUI generator are not counted. Fails below COVER_MIN percent.
# Runs in the dev image.
set -euo pipefail
out=${COVERAGE:-coverage.out}
min=${COVER_MIN:-90}
pkgs=$(go list ./internal/... | paste -sd, -)
mapfile -t tests < <(go list ./... | grep -v -e /tools/ -e /cmd/ -e /data/oui/gen)

# Per-package percentages are misleading with -coverpkg (each is relative to
# all of internal/), so only the total is reported.
CGO_ENABLED=1 go test -count=1 -race -covermode=atomic -coverpkg="$pkgs" -coverprofile="$out" "${tests[@]}" |
	sed -E 's/[[:space:]]+coverage: .*//'
total=$(go tool cover -func="$out" | awk '/^total:/ { sub(/%/, "", $3); print $3 }')
echo "Coverage of internal/: ${total}% (minimum ${min}%)"
if ! awk -v t="$total" -v m="$min" 'BEGIN { exit !(t + 0 >= m + 0) }'; then
	echo "Coverage ${total}% is below the ${min}% minimum" >&2
	exit 1
fi
