#!/usr/bin/env bash
# A throwaway Docker dev box: sshd, plus dev servers that appear on a delay so
# you can watch tunnels arrive. Recreated each run, so its services are
# genuinely new rather than something that was already listening.
set -euo pipefail
cd "$(dirname "$0")/.."

name=devtun-sandbox
image=devtun-sandbox:latest

build() { docker build -q -t "$image" -f e2e/Dockerfile e2e >/dev/null; }

case "${1:-start}" in
start)
	docker rm -f "$name" >/dev/null 2>&1 || true
	build
	# Authorise whatever keys you already have, so the box behaves like a real
	# host rather than a special case.
	keys="$(cat ~/.ssh/*.pub 2>/dev/null || true)"
	if command -v ssh-add >/dev/null && ssh-add -L >/dev/null 2>&1; then
		keys="$keys
$(ssh-add -L)"
	fi
	[ -n "${keys// /}" ] || { echo "no SSH public keys found in ~/.ssh or your agent" >&2; exit 1; }
	docker run -d --name "$name" -P -e "AUTHORIZED_KEYS=$keys" "$image" >/dev/null
	echo "sandbox up on port $(docker port "$name" 22 | head -1 | cut -d: -f2)"
	;;
port) docker port "$name" 22 | head -1 | cut -d: -f2 ;;
shell) exec docker exec -it "$name" bash ;;
stop) docker rm -f "$name" >/dev/null 2>&1 || true; echo "sandbox down" ;;
*) echo "usage: sandbox.sh [start|stop|shell|port]" >&2; exit 2 ;;
esac
