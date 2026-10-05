#!/bin/sh
# Runs every Fuzz* target in the module for FUZZTIME each. Runs in the dev
# image.
set -eu
FUZZTIME=${FUZZTIME:-30s}
echo "Fuzzing every target (FUZZTIME=$FUZZTIME)"
found=0
for pkg in $(go list ./...); do
	for f in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
		found=1
		echo "Fuzzing $pkg $f"
		go test -run='^$' -fuzz="^$f\$" -fuzztime="$FUZZTIME" "$pkg"
	done
done
[ "$found" = 1 ] || echo "No fuzz targets found"
