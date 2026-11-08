package opcli

import "context"

// RunHelper is never the answer on Windows, which runs op directly: there is
// no /dev/tty for op to open behind devtun's back, and no session to share.
func RunHelper([]string) (code int, handled bool) { return 0, false }

func newSpawner(path string) spawner { return direct{path: path} }

// direct runs each op as a plain child of devtun.
type direct struct{ path string }

func (d direct) run(ctx context.Context, args []string, stdin []byte) (Result, error) {
	return execOp(ctx, d.path, args, stdin)
}

func (direct) close() error { return nil }
