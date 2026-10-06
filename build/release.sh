#!/bin/sh
# Builds the static release binaries (release) or the capcheck tool (tools)
# for linux/amd64 and linux/arm64. Runs in the dev image; LDFLAGS comes from
# the Makefile.
set -eu
mode=${1:-release}
targets="linux/amd64 linux/arm64"

case $mode in
release)
	rm -rf dist/lan-sentinel-* dist/SHA256SUMS
	mkdir -p dist
	for t in $targets; do
		os=${t%/*} arch=${t#*/}
		out=dist/lan-sentinel-$os-$arch
		echo "Building $out"
		GOOS=$os GOARCH=$arch go build -trimpath -ldflags "${LDFLAGS:-}" -o "$out" ./cmd/lan-sentinel
		file "$out" | grep -q "statically linked" || { echo "$out is not statically linked" >&2; exit 1; }
	done
	(cd dist && sha256sum lan-sentinel-* >SHA256SUMS && cat SHA256SUMS)
	;;
tools)
	rm -rf dist/tools
	mkdir -p dist/tools
	for t in $targets; do
		os=${t%/*} arch=${t#*/}
		out=dist/tools/capcheck-$os-$arch
		echo "Building $out"
		GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "$out" ./tools/capcheck
	done
	(cd dist/tools && sha256sum capcheck-* >SHA256SUMS && cat SHA256SUMS)
	;;
*)
	echo "usage: $0 release|tools" >&2
	exit 64
	;;
esac
