#!/bin/sh
# Prints the next release version for a bump (patch, minor or major) from
# the highest vMAJOR.MINOR.PATCH tag; without any such tag the first release
# is v0.0.1, whatever the bump. Used by .github/workflows/release.yml.
set -eu
bump=${1:-patch}
case $bump in
patch | minor | major) ;;
*)
	echo "usage: $0 patch|minor|major" >&2
	exit 64
	;;
esac
last=$(git tag --list 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -t. -k1.2,1n -k2,2n -k3,3n | tail -n 1 || true)
if [ -z "$last" ]; then
	echo v0.0.1
	exit 0
fi
IFS=. read -r major minor patch <<EOV
${last#v}
EOV
case $bump in
major) echo "v$((major + 1)).0.0" ;;
minor) echo "v$major.$((minor + 1)).0" ;;
patch) echo "v$major.$minor.$((patch + 1))" ;;
esac
