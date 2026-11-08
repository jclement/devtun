//go:build !windows

package opcli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeOpEnv makes the test binary behave as op. The same binary is also the
// session helper — RunHelper recognises it by argv[0] — so these tests run the
// real helper, in a real session of its own, starting a stand-in op whose
// only job is to report what it can see.
const fakeOpEnv = "OPCLI_TEST_FAKE_OP"

func TestMain(m *testing.M) {
	if code, handled := RunHelper(os.Args); handled {
		os.Exit(code)
	}
	if os.Getenv(fakeOpEnv) == "1" {
		os.Exit(fakeOp(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeOp is the stand-in op.
//
//	sid            print this process's session ID
//	tty            say whether /dev/tty can be opened
//	echo ARGS...   print the account and arguments, copy stdin, complain on stderr, exit 3
//	sleep PIDFILE  write the pid to PIDFILE and hang
func fakeOp(args []string) int {
	account := ""
	if len(args) >= 2 && args[0] == "--account" {
		account, args = args[1], args[2:]
	}
	if len(args) == 0 {
		return 2
	}
	switch args[0] {
	case "sid":
		sid, err := getsid()
		if err != nil {
			return 2
		}
		fmt.Print(sid)
	case "tty":
		if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
			_ = f.Close()
			fmt.Print("has-tty")
		} else {
			fmt.Print("no-tty")
		}
	case "echo":
		fmt.Printf("account=%s args=%s stdin=", account, strings.Join(args[1:], ","))
		_, _ = io.Copy(os.Stdout, os.Stdin)
		fmt.Fprint(os.Stderr, "complaint")
		return 3
	case "sleep":
		_ = os.WriteFile(args[1], []byte(strconv.Itoa(os.Getpid())), 0o600)
		time.Sleep(time.Minute)
	}
	return 0
}

// getsid is getsid(2) for the calling process. The syscall package has no
// wrapper for it on Linux.
func getsid() (int, error) {
	sid, _, errno := syscall.RawSyscall(syscall.SYS_GETSID, 0, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(sid), nil
}

func newTestRunner(t *testing.T) *Runner {
	t.Helper()
	t.Setenv(fakeOpEnv, "1")
	// Under -race every process sleeps a second on its way out; the helper
	// and each fake op are processes.
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r := &Runner{Path: self, Timeout: 30 * time.Second}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func run(t *testing.T, r *Runner, argv ...string) Result {
	t.Helper()
	result, err := r.Run(context.Background(), "", argv, nil)
	if err != nil {
		t.Fatalf("op %v: %v", argv, err)
	}
	return result
}

func sessionOf(r *Runner) *session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.spawn.(*session)
}

func (s *session) live() (*helper, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current, s.starts
}

// The point of the helper: every op shares one session, which is what
// 1Password's approval is keyed on, and it is not devtun's session.
func TestCallsShareOneSessionThatIsNotDevtuns(t *testing.T) {
	r := newTestRunner(t)

	first := strings.TrimSpace(string(run(t, r, "sid").Stdout))
	second := strings.TrimSpace(string(run(t, r, "sid").Stdout))
	if first == "" || first != second {
		t.Fatalf("op ran in sessions %q and %q; want one shared session", first, second)
	}
	own, err := getsid()
	if err != nil {
		t.Fatal(err)
	}
	if first == strconv.Itoa(own) {
		t.Fatalf("op ran in devtun's own session %d; want the helper's", own)
	}

	h, starts := sessionOf(r).live()
	if starts != 1 {
		t.Fatalf("started %d helpers for two calls; want 1", starts)
	}
	if first != strconv.Itoa(h.cmd.Process.Pid) {
		t.Fatalf("op's session %s is not led by the helper (pid %d)", first, h.cmd.Process.Pid)
	}
}

// The guarantee from "Keep op off the terminal": op cannot open a terminal,
// so it can never draw an account picker over the interface.
func TestOpHasNoTerminal(t *testing.T) {
	r := newTestRunner(t)
	if got := string(run(t, r, "tty").Stdout); got != "no-tty" {
		t.Fatalf("op reported %q; want no-tty", got)
	}
}

func TestRunPassesAccountArgumentsStdinAndExit(t *testing.T) {
	r := newTestRunner(t)
	result, err := r.Run(context.Background(), "work.1password.com", []string{"echo", "a", "b"}, []byte("input"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "account=work.1password.com args=a,b stdin=input"; string(result.Stdout) != want {
		t.Errorf("stdout = %q; want %q", result.Stdout, want)
	}
	if string(result.Stderr) != "complaint" {
		t.Errorf("stderr = %q; want complaint", result.Stderr)
	}
	if result.Exit != 3 {
		t.Errorf("exit = %d; want 3", result.Exit)
	}
}

func TestConcurrentCallsGetTheirOwnAnswers(t *testing.T) {
	r := newTestRunner(t)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			arg := strconv.Itoa(i)
			result, err := r.Run(context.Background(), "", []string{"echo", arg}, nil)
			if err != nil {
				t.Errorf("call %d: %v", i, err)
				return
			}
			if want := "account= args=" + arg + " stdin="; string(result.Stdout) != want {
				t.Errorf("call %d got %q; want %q", i, result.Stdout, want)
			}
		}()
	}
	wg.Wait()
	if _, starts := sessionOf(r).live(); starts != 1 {
		t.Fatalf("started %d helpers; want 1", starts)
	}
}

// A helper that dies is replaced on the next call. The new one is a new
// session — 1Password will ask once more — but devtun keeps working.
func TestHelperIsReplacedAfterItDies(t *testing.T) {
	r := newTestRunner(t)
	before := string(run(t, r, "sid").Stdout)

	h, _ := sessionOf(r).live()
	if err := h.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-h.done

	after := string(run(t, r, "sid").Stdout)
	if after == before {
		t.Fatalf("still in session %s after the helper died", before)
	}
	if _, starts := sessionOf(r).live(); starts != 2 {
		t.Fatalf("started %d helpers; want 2", starts)
	}
}

func TestTimeoutKillsOpButKeepsTheHelper(t *testing.T) {
	r := newTestRunner(t)
	r.Timeout = 500 * time.Millisecond
	pidFile := filepath.Join(t.TempDir(), "pid")

	_, err := r.Run(context.Background(), "", []string{"sleep", pidFile}, nil)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v; want a timeout", err)
	}
	waitGone(t, readPid(t, pidFile))

	r.Timeout = 30 * time.Second
	run(t, r, "sid")
	if _, starts := sessionOf(r).live(); starts != 1 {
		t.Fatalf("started %d helpers; want the first one kept", starts)
	}
}

// Close ends the helper and whatever op it is running. Closing the helper's
// stdin is also what happens when devtun dies, so this covers that path too.
func TestCloseStopsTheHelperAndRunningOp(t *testing.T) {
	r := newTestRunner(t)
	pidFile := filepath.Join(t.TempDir(), "pid")

	errs := make(chan error, 1)
	go func() {
		_, err := r.Run(context.Background(), "", []string{"sleep", pidFile}, nil)
		errs <- err
	}()
	op := readPid(t, pidFile)
	h, _ := sessionOf(r).live()

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.done:
	default:
		t.Fatal("Close returned with the helper still running")
	}
	waitGone(t, op)
	if err := <-errs; err == nil {
		t.Fatal("the interrupted call reported success")
	}
	if _, err := r.Run(context.Background(), "", []string{"sid"}, nil); !errors.Is(err, errClosed) {
		t.Fatalf("Run after Close: err = %v; want errClosed", err)
	}
}

func TestCloseBeforeAnyRun(t *testing.T) {
	r := newTestRunner(t)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background(), "", []string{"sid"}, nil); !errors.Is(err, errClosed) {
		t.Fatalf("err = %v; want errClosed", err)
	}
}

func TestRunHelperIgnoresOrdinaryInvocations(t *testing.T) {
	for _, argv := range [][]string{
		{"devtun"},
		{"devtun", "bedev"},
		{"op", "read"},
		{helperName},
		{helperName, "/usr/bin/op", "extra"},
	} {
		if _, handled := RunHelper(argv); handled {
			t.Errorf("RunHelper(%q) claimed it", argv)
		}
	}
}

func readPid(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			pid, err := strconv.Atoi(string(data))
			if err != nil {
				t.Fatal(err)
			}
			return pid
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("op never started")
	return 0
}

// waitGone waits for a process to disappear. op's parent is the helper, not
// this test, so there is nothing here to reap: gone means reaped by whoever
// owns it.
func waitGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("op (pid %d) is still running", pid)
}
