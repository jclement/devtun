#!/usr/bin/env bash
# Bump the version, tag, and push — CI does the build.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -z "$(git status --porcelain)" ] || { echo "working tree is dirty; commit or stash first" >&2; exit 1; }

current="$(git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0)"
IFS=. read -r major minor patch <<<"${current#v}"
echo "current: $current"
printf 'bump [p]atch / [m]inor / [M]ajor? '
read -r choice
case "$choice" in
	p) patch=$((patch + 1)) ;;
	m) minor=$((minor + 1)); patch=0 ;;
	M) major=$((major + 1)); minor=0; patch=0 ;;
	*) echo "aborted"; exit 1 ;;
esac
next="v$major.$minor.$patch"

printf 'tag %s and push? [y/N] ' "$next"
read -r confirm
[ "$confirm" = y ] || { echo "aborted"; exit 1; }

git tag -a "$next" -m "$next"
git push origin "$next"
echo "pushed $next — CI is building the release"
