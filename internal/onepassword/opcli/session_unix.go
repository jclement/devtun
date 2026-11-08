//go:build !windows

package opcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Why op runs inside a helper's session
//
// 1Password's CLI integration does not authorise the op binary, or devtun: it
// authorises a session, in the setsid(2) sense, which is what a terminal
// window normally is. op reports getsid(0) to the desktop app, an approval
// lasts for that session (until ten minutes idle), and any op in the same
// session after that runs without asking. Measured on Linux with op 2.41: two
// calls each in a session of their own asked twice; two calls from one
// tty-less session asked once, and so did two from a terminal. The tty plays
// no part.
//
// op must still never reach devtun's terminal. With several accounts signed in
// and none chosen, op opens /dev/tty to ask which to use, and inheriting
// devtun's terminal it drew that picker over --tui and read its keystrokes. So
// op must run in a session that has no terminal — and it must be the *same*
// session every time, or each call is a stranger to 1Password and asks again,
// which is what starting each op with Setsid did.
//
// Only a process inside a session can start another in it, so a helper holds
// the session: devtun re-executes itself under helperName, in a new session
// with pipes for stdio and no controlling terminal, and the helper starts every
// op. It never opens a terminal, and op, not being a session leader, cannot
// acquire one, so /dev/tty fails and op reports an error instead of asking.
//
// The helper lives as long as the Runner: it is started on first use, started
// again if it dies (which costs one more approval — the old session is gone),
// and it exits when its stdin closes, whether because devtun closed the Runner
// or because devtun died. Either way it kills any op still running.

// helperName is argv[0] of the helper, and how RunHelper recognises it. It is
// not a name anyone types: it only has to be distinct from the shim names that
// main dispatches on, and readable in ps.
const helperName = "devtun-op-session"

// closeGrace is how long Close waits for the helper to leave on its own
// before killing it and everything it started.
const closeGrace = 5 * time.Second

// RunHelper serves as the op session helper when argv says this process is
// one, and reports whether it did. main calls it before anything else.
func RunHelper(argv []string) (code int, handled bool) {
	if len(argv) != 2 || filepath.Base(argv[0]) != helperName {
		return 0, false
	}
	return serveHelper(os.Stdin, os.Stdout, argv[1]), true
}

// helperRequest is one message from devtun to the helper: run op with Args
// and Stdin, or, with Cancel, stop the run with that ID.
type helperRequest struct {
	ID     uint64   `json:"id"`
	Cancel bool     `json:"cancel,omitempty"`
	Args   []string `json:"args,omitempty"`
	Stdin  []byte   `json:"stdin,omitempty"`
}

// helperResponse is the outcome of the run with that ID. Error is set only
// when op could not be run at all.
type helperResponse struct {
	ID     uint64 `json:"id"`
	Exit   int    `json:"exit"`
	Stdout []byte `json:"stdout,omitempty"`
	Stderr []byte `json:"stderr,omitempty"`
	Error  string `json:"error,omitempty"`
}

// serveHelper is the helper's whole life: run each request concurrently,
// answer in whatever order they finish, and on end of input kill what is left
// and leave. opPath is fixed at start, so the pipe can choose arguments but
// never which program runs.
func serveHelper(in io.Reader, out io.Writer, opPath string) int {
	ctx, stopAll := context.WithCancel(context.Background())
	defer stopAll()

	var (
		mu      sync.Mutex // guards enc and running
		enc     = json.NewEncoder(out)
		running = map[uint64]context.CancelFunc{}
		wg      sync.WaitGroup
	)
	dec := json.NewDecoder(in)
	for {
		var request helperRequest
		if err := dec.Decode(&request); err != nil {
			break // devtun closed the pipe, or is gone
		}
		if request.Cancel {
			mu.Lock()
			if cancel, ok := running[request.ID]; ok {
				cancel()
			}
			mu.Unlock()
			continue
		}

		callCtx, cancel := context.WithCancel(ctx)
		mu.Lock()
		running[request.ID] = cancel
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			result, err := execOp(callCtx, opPath, request.Args, request.Stdin)
			response := helperResponse{ID: request.ID, Exit: result.Exit, Stdout: result.Stdout, Stderr: result.Stderr}
			if err != nil {
				response.Error = err.Error()
			}
			mu.Lock()
			defer mu.Unlock()
			delete(running, request.ID)
			_ = enc.Encode(response)
		}()
	}
	stopAll()
	wg.Wait()
	return 0
}

func newSpawner(path string) spawner {
	return &session{path: path}
}

// session is devtun's side of the helper: it starts one, keeps it, replaces
// it if it dies, and stops it on close.
type session struct {
	path   string
	nextID atomic.Uint64

	mu      sync.Mutex
	current *helper
	closed  bool
	starts  int // helpers started, for tests
}

func (s *session) run(ctx context.Context, args []string, stdin []byte) (Result, error) {
	for attempt := 0; ; attempt++ {
		h, err := s.helper()
		if err != nil {
			return Result{}, err
		}
		id := s.nextID.Add(1)
		reply, err := h.send(helperRequest{ID: id, Args: args, Stdin: stdin})
		if err != nil {
			// The request never reached the helper, so op did not run and
			// trying once more on a fresh helper cannot run it twice.
			h.retire()
			if attempt == 0 {
				continue
			}
			return Result{}, fmt.Errorf("the 1Password session helper is not answering: %w", err)
		}
		select {
		case response, ok := <-reply:
			if !ok {
				return Result{}, fmt.Errorf("the 1Password session helper exited while op was running%s", h.why())
			}
			result := Result{Exit: response.Exit, Stdout: response.Stdout, Stderr: response.Stderr}
			if response.Error != "" {
				return result, errors.New(response.Error)
			}
			return result, nil
		case <-ctx.Done():
			h.cancel(id)
			return Result{}, ctx.Err()
		}
	}
}

// helper returns the live helper, starting one if there is none.
func (s *session) helper() (*helper, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errClosed
	}
	if s.current != nil && !s.current.gone() {
		return s.current, nil
	}
	h, err := startHelper(s.path)
	if err != nil {
		return nil, err
	}
	s.current = h
	s.starts++
	return h, nil
}

func (s *session) close() error {
	s.mu.Lock()
	h := s.current
	s.current = nil
	s.closed = true
	s.mu.Unlock()
	if h != nil {
		h.stop()
	}
	return nil
}

// helper is one running helper process.
type helper struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	done  chan struct{} // closed once the process has exited and been reaped

	writeMu sync.Mutex // serialises enc
	enc     *json.Encoder

	mu      sync.Mutex
	pending map[uint64]chan helperResponse
	ended   bool // reaped
	retired bool // input closed; on its way out
	exitErr error
	stderr  tail
}

func startHelper(opPath string) (*helper, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("finding devtun's own executable to start the 1Password session helper: %w", err)
	}
	// Not CommandContext: the helper outlives every request, and Close is
	// what ends it.
	cmd := &exec.Cmd{
		Path: self,
		Args: []string{helperName, opPath},
		Env:  os.Environ(),
		// A session of its own and no controlling terminal: the session every
		// op shares, and the reason none of them can reach devtun's terminal.
		SysProcAttr: &syscall.SysProcAttr{Setsid: true},
	}
	h := &helper{cmd: cmd, done: make(chan struct{}), pending: map[uint64]chan helperResponse{}}
	// A helper that panics must not print over the interface either, so its
	// stderr is kept, briefly, for the error that reports its death.
	cmd.Stderr = &h.stderr
	if h.stdin, err = cmd.StdinPipe(); err != nil {
		return nil, fmt.Errorf("starting the 1Password session helper: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("starting the 1Password session helper: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting the 1Password session helper: %w", err)
	}
	h.enc = json.NewEncoder(h.stdin)
	go h.read(stdout)
	return h, nil
}

// read delivers responses until the helper stops talking, then reaps it and
// fails whatever was still waiting.
func (h *helper) read(stdout io.Reader) {
	dec := json.NewDecoder(stdout)
	for {
		var response helperResponse
		if err := dec.Decode(&response); err != nil {
			break
		}
		h.mu.Lock()
		reply := h.pending[response.ID]
		delete(h.pending, response.ID)
		h.mu.Unlock()
		if reply != nil {
			reply <- response
		}
	}
	_ = h.stdin.Close()
	err := h.cmd.Wait()

	h.mu.Lock()
	h.ended = true
	h.exitErr = err
	for id, reply := range h.pending {
		close(reply)
		delete(h.pending, id)
	}
	h.mu.Unlock()
	close(h.done)
}

func (h *helper) send(request helperRequest) (<-chan helperResponse, error) {
	reply := make(chan helperResponse, 1)
	h.mu.Lock()
	if h.ended || h.retired {
		h.mu.Unlock()
		return nil, errors.New("helper has exited")
	}
	h.pending[request.ID] = reply
	h.mu.Unlock()

	h.writeMu.Lock()
	err := h.enc.Encode(request)
	h.writeMu.Unlock()
	if err != nil {
		h.mu.Lock()
		delete(h.pending, request.ID)
		h.mu.Unlock()
		return nil, err
	}
	return reply, nil
}

// cancel abandons a run: nobody is waiting for its answer any more, and the
// helper is asked to kill it.
func (h *helper) cancel(id uint64) {
	h.mu.Lock()
	delete(h.pending, id)
	h.mu.Unlock()
	h.writeMu.Lock()
	_ = h.enc.Encode(helperRequest{ID: id, Cancel: true})
	h.writeMu.Unlock()
}

func (h *helper) gone() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ended || h.retired
}

// retire closes the helper's input, which ends it; the next run starts
// another. It does not wait.
func (h *helper) retire() {
	h.mu.Lock()
	h.retired = true
	h.mu.Unlock()
	_ = h.stdin.Close()
}

// stop ends the helper and everything it started, waiting for it to go.
func (h *helper) stop() {
	h.retire()
	select {
	case <-h.done:
		return
	case <-time.After(closeGrace):
	}
	// A helper that will not leave is killed along with its process group,
	// which — the helper being a session leader — is every op it started.
	_ = syscall.Kill(-h.cmd.Process.Pid, syscall.SIGKILL)
	<-h.done
}

// why describes how the helper ended, for the error a caller sees.
func (h *helper) why() string {
	<-h.done
	h.mu.Lock()
	defer h.mu.Unlock()
	var parts []string
	if h.exitErr != nil {
		parts = append(parts, h.exitErr.Error())
	}
	if s := strings.TrimSpace(h.stderr.String()); s != "" {
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return ""
	}
	return ": " + strings.Join(parts, ": ")
}

// tail keeps the last few kilobytes written to it.
type tail struct {
	mu  sync.Mutex
	buf []byte
}

const tailMax = 4 << 10

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > tailMax {
		t.buf = t.buf[len(t.buf)-tailMax:]
	}
	return len(p), nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}
