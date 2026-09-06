#!/usr/bin/env bash
# Build, then attach to a host — or to a throwaway Docker dev box if none is
# given, so you can watch tunnels arrive without involving a real machine.
set -euo pipefail
cd "$(dirname "$0")/.."

go build -o bin/devtun ./cmd/devtun

if [ $# -gt 0 ]; then
	exec ./bin/devtun --tui "$@"
fi

./scripts/sandbox.sh start
port="$(./scripts/sandbox.sh port)"
exec ./bin/devtun --tui --host-key no -p "$port" "root@127.0.0.1"
