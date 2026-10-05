#!/bin/sh
# Builds the binaries the Docker test suites run (test/net, test/systemd) into
# OUT (default .build/test), for the dev container's architecture, which is
# the Docker host's.
set -eu
OUT=${1:-.build/test}
rm -rf "$OUT"
mkdir -p "$OUT"
go build -trimpath -o "$OUT/lan-sentinel" ./cmd/lan-sentinel
go build -trimpath -o "$OUT/capcheck" ./tools/capcheck
for pkg in $(go list -tags nettest -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' ./test/net/...); do
	go test -c -tags nettest -o "$OUT/$(echo "$pkg" | tr / _).test" "$pkg"
done
echo "Test binaries in $OUT: $(ls "$OUT" | tr '\n' ' ')"
