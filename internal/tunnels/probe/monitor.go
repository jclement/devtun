package probe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/jclement/devtun/internal/event"
	"io"
	"strings"
	"sync"
	"time"
)

// Runner starts a command on the remote host. service.Host satisfies it in
// production; tests supply a local one.
type Runner interface {
	// Run executes `sh -s` remotely with script on stdin. It returns once
	// the command exits or ctx is canceled. Output lines are delivered to
	// stdout as they arrive.
	Run(ctx context.Context, script string, stdout io.Writer) error
	// Output runs a short-lived command and collects its complete output.
	Output(ctx context.Context, script string) (string, error)
}

// Info describes the remote prober once it has started.
type Info struct {
	Version int
	Mode    Mode
	OS      string
}

// Monitor streams snapshots of the remote host's listening services.
type Monitor struct {
	runner   Runner
	interval time.Duration

	mu       sync.Mutex
	cmdlines map[int]string // pid -> command line, resolved once per pid
	unknown  map[int]bool   // pids awaiting resolution
}

// NewMonitor returns a Monitor that scans every interval.
func NewMonitor(r Runner, interval time.Duration) *Monitor {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &Monitor{
		runner:   r,
		interval: interval,
		cmdlines: map[int]string{},
		unknown:  map[int]bool{},
	}
}

// Result is one delivered scan.
type Result struct {
	Snapshot Snapshot
	At       time.Time
}

// Run drives the remote prober until ctx is canceled or the session ends,
// delivering each scan to onScan. onReady is called once, when the remote has
// reported which discovery mode it selected.
//
// Run always returns a non-nil error describing why the stream stopped; a
// clean remote exit is reported as io.EOF so callers can decide whether to
// reconnect.
func (m *Monitor) Run(ctx context.Context, onReady func(Info), onScan func(Result)) error {
	// The runner gets its own cancellable context so that a parse failure can
	// tear the session down. Without this, a remote that reports an error and
	// then holds the session open would hang here forever.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	pr, pw := io.Pipe()

	var parseErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		parseErr = m.consume(ctx, runCtx, pr, onReady, onScan)
		// Unblock the runner if the parser stopped first.
		pr.CloseWithError(parseErr)
		cancel()
	}()

	runErr := m.runner.Run(runCtx, Script(m.interval), pw)
	pw.CloseWithError(io.EOF)
	wg.Wait()

	switch {
	case parseErr != nil && !errors.Is(parseErr, io.EOF):
		return parseErr
	case runErr != nil:
		return runErr
	default:
		return io.EOF
	}
}

// consume reads the framed prober stream. resolveCtx outlives the session and
// is used for lazy command-line lookups; runCtx tracks the session itself.
func (m *Monitor) consume(resolveCtx, runCtx context.Context, r io.Reader, onReady func(Info), onScan func(Result)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var (
		info      Info
		ready     bool
		inScan    bool
		inSockMap bool
		body      strings.Builder
		sockMap   strings.Builder
	)

	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, markError):
			return fmt.Errorf("remote prober: %s", strings.TrimSpace(strings.TrimPrefix(line, markError)))

		case strings.HasPrefix(line, markReady):
			f := strings.Fields(line)
			info = Info{Version: 1, Mode: ModeSS}
			if len(f) >= 3 {
				mode, err := ParseMode(f[2])
				if err != nil {
					return err
				}
				info.Mode = mode
			}
			if len(f) >= 4 {
				info.OS = f[3]
			}
			ready = true
			if onReady != nil {
				onReady(info)
			}

		case line == markScan:
			inScan, inSockMap = true, false
			body.Reset()
			sockMap.Reset()

		case line == markSockMap:
			inSockMap = true

		case line == markEnd:
			if !inScan {
				continue
			}
			inScan, inSockMap = false, false
			snap := m.build(resolveCtx, info.Mode, body.String(), sockMap.String())
			if onScan != nil {
				onScan(Result{Snapshot: snap, At: time.Now()})
			}

		case inSockMap:
			sockMap.WriteString(line)
			sockMap.WriteByte('\n')

		case inScan:
			body.WriteString(line)
			body.WriteByte('\n')
		}
		if runCtx.Err() != nil {
			return runCtx.Err()
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if !ready {
		return errors.New("remote prober produced no output; is `sh` available on the remote?")
	}
	return io.EOF
}

// build turns one scan's raw output into a Snapshot, filling in command lines
// already known and queueing any new pids for resolution.
func (m *Monitor) build(ctx context.Context, mode Mode, body, sockMap string) Snapshot {
	var ls []Listener
	switch mode {
	case ModeSS:
		ls = ParseSS(body)
	case ModeLsof:
		ls = ParseLsof(body)
	case ModeNetstat:
		ls = ParseNetstat(body)
	case ModeProc:
		ls = ParseProc(body, sockMap)
	}
	snap := merge(ls)

	m.mu.Lock()
	var need []int
	for port, svc := range snap {
		if svc.PID == 0 {
			continue
		}
		if cmd, ok := m.cmdlines[svc.PID]; ok {
			// A command line is the longest remote-controlled string devtun
			// displays, so it is both sanitised and bounded.
			svc.Cmd = event.SanitizeTo(cmd, 200)
			snap[port] = svc
		} else if !m.unknown[svc.PID] {
			m.unknown[svc.PID] = true
			need = append(need, svc.PID)
		}
	}
	m.mu.Unlock()

	if len(need) > 0 {
		go m.resolve(ctx, need)
	}
	return snap
}

// resolve fetches command lines for pids seen for the first time. Failures are
// silent: the process name from the listing tool remains as a fallback.
func (m *Monitor) resolve(ctx context.Context, pids []int) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, err := m.runner.Output(ctx, CmdlineScript(pids))
	if err != nil {
		m.mu.Lock()
		for _, p := range pids {
			delete(m.unknown, p) // allow a retry on a later scan
		}
		m.mu.Unlock()
		return
	}
	found := ParseCmdlines(out)
	m.mu.Lock()
	for pid, cmd := range found {
		m.cmdlines[pid] = cmd
	}
	m.mu.Unlock()
}

// Cmdline returns a previously resolved command line, if any.
func (m *Monitor) Cmdline(pid int) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cmdlines[pid]
	return c, ok
}
