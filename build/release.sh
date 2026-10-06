#!/bin/sh
# Builds the static release binaries (release), the capcheck tool (tools),
# or the release tarballs from both (package) for linux/amd64 and
# linux/arm64. Runs in the dev image; LDFLAGS, VERSION and SOURCE_DATE_EPOCH
# come from the Makefile.
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
package)
	# One tarball per target: the binary, capcheck, the reference deploy
	# files and the binaries' checksums, in a directory named like the
	# tarball. Reproducible: fixed order, owner, modes and mtime (the
	# commit's), and gzip without a timestamp.
	: "${VERSION:?VERSION is required}"
	epoch=${SOURCE_DATE_EPOCH:-0}
	rm -rf dist/release
	mkdir -p dist/release
	for t in $targets; do
		os=${t%/*} arch=${t#*/}
		name=lan-sentinel-$VERSION-$os-$arch
		stage=dist/release/$name
		for f in dist/lan-sentinel-$os-$arch dist/tools/capcheck-$os-$arch; do
			[ -f "$f" ] || { echo "$f missing: build release and tools first" >&2; exit 1; }
		done
		mkdir -p "$stage"
		cp "dist/lan-sentinel-$os-$arch" "$stage/lan-sentinel"
		cp "dist/tools/capcheck-$os-$arch" "$stage/capcheck"
		cp deploy/lan-sentinel.service deploy/config.yaml deploy/README.md "$stage/"
		(cd "$stage" && sha256sum lan-sentinel capcheck >SHA256SUMS)
		chmod 0755 "$stage" "$stage/lan-sentinel" "$stage/capcheck"
		chmod 0644 "$stage"/lan-sentinel.service "$stage"/config.yaml "$stage"/README.md "$stage"/SHA256SUMS
		echo "Packing dist/release/$name.tar.gz"
		tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner --format=gnu \
			-C dist/release -cf - "$name" | gzip -9n >"dist/release/$name.tar.gz"
		rm -rf "$stage"
	done
	(cd dist/release && sha256sum ./*.tar.gz | sed 's| \./| |' >SHA256SUMS && cat SHA256SUMS)
	;;
*)
	echo "usage: $0 release|tools|package" >&2
	exit 64
	;;
esac
