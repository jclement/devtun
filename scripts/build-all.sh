#!/usr/bin/env bash
# Cross-build devtun for every platform a remote dev box might be.
#
# `devtun install` and the automatic sync look in dist/ first, so a development
# checkout can push a helper to an arm64 Linux box from an arm64 Mac without
# cutting a release. The names must match what internal/session/shimsync.go
# looks for: devtun-<goos>-<goarch>.
set -euo pipefail
cd "$(dirname "$0")/.."

version="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
pkg=github.com/jclement/devtun/internal/buildinfo
flags="-s -w -X $pkg.version=$version -X $pkg.commit=$commit -X $pkg.buildDate=$date"

mkdir -p dist
for target in linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64; do
	goos="${target%/*}" goarch="${target#*/}"
	out="dist/devtun-$goos-$goarch"
	echo "  $out"
	CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
		go build -trimpath -ldflags "$flags" -o "$out" ./cmd/devtun
done
echo "built $version"
