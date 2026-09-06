package tunnels

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Dialer opens a connection from the remote host. *ssh.Client satisfies it, and
// so does net.Dialer, which is what the tests use.
type Dialer interface {
	Dial(network, addr string) (net.Conn, error)
}

// forwarder accepts local connections and pipes each one over a fresh channel
// to the remote service, tallying traffic as it goes.
type forwarder struct {
	ln       net.Listener
	dialer   Dialer
	dialAddr string

	local    int
	remapped bool
	created  time.Time

	in     atomic.Uint64
	out    atomic.Uint64
	active atomic.Int64
	total  atomic.Uint64
	last   atomic.Int64 // unix nano of most recent byte, 0 if never

	lastErr atomic.Pointer[string]

	// onScheme is called with what the service turned out to be, the first
	// time a reply says anything conclusive.
	onScheme func(Scheme)
	sniffed  atomic.Bool

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

func newForwarder(ln net.Listener, d Dialer, dialAddr string, remapped bool, now time.Time, onScheme func(Scheme)) *forwarder {
	f := &forwarder{
		onScheme: onScheme,
		ln:       ln,
		dialer:   d,
		dialAddr: dialAddr,
		local:    LocalPort(ln),
		remapped: remapped,
		created:  now,
		done:     make(chan struct{}),
	}
	f.wg.Add(1)
	go f.accept()
	return f
}

func (f *forwarder) accept() {
	defer f.wg.Done()
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			select {
			case <-f.done:
				return
			default:
			}
			if isTemporary(err) {
				continue
			}
			f.setErr(err)
			return
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			f.handle(conn)
		}()
	}
}

// handle bridges one accepted local connection to the remote service.
func (f *forwarder) handle(local net.Conn) {
	defer func() { _ = local.Close() }()

	remote, err := f.dialer.Dial("tcp", f.dialAddr)
	if err != nil {
		f.setErr(err)
		return
	}
	defer func() { _ = remote.Close() }()

	f.active.Add(1)
	f.total.Add(1)
	defer f.active.Add(-1)

	var wg sync.WaitGroup
	wg.Add(2)
	// Local -> remote is "out"; remote -> local is "in". Both directions are
	// half-closed on EOF so a client that shuts down writing (curl, HTTP/1.0)
	// still receives the response.
	go func() {
		defer wg.Done()
		n, _ := io.Copy(remote, local)
		f.out.Add(uint64(n))
		f.touch()
		halfClose(remote)
	}()
	go func() {
		defer wg.Done()
		n := f.copyReply(local, remote)
		f.in.Add(n)
		f.touch()
		halfClose(local)
	}()
	wg.Wait()
}

// copyReply forwards the service's reply, classifying it from its opening
// bytes on the way past. The bytes are relayed unchanged; nothing is withheld
// or injected.
func (f *forwarder) copyReply(dst io.Writer, src io.Reader) uint64 {
	var total uint64

	if f.onScheme != nil && f.sniffed.CompareAndSwap(false, true) {
		// A single Read, never ReadFull: a reply shorter than the buffer that
		// then waits for the client — which plenty of protocols do — would
		// block forever, wedging the tunnel on its first connection.
		head := make([]byte, 8)
		n, err := src.Read(head)
		if n > 0 {
			if scheme := SniffScheme(head[:n]); scheme != SchemeUnknown {
				f.onScheme(scheme)
			}
			written, werr := dst.Write(head[:n])
			total += uint64(written)
			if werr != nil {
				return total
			}
		}
		if err != nil {
			return total
		}
	}

	n, _ := io.Copy(dst, src)
	return total + uint64(n)
}

// halfClose shuts down the write side if the connection supports it, so the
// peer sees EOF without the whole connection being torn down.
func halfClose(c net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

func (f *forwarder) touch() { f.last.Store(time.Now().UnixNano()) }

func (f *forwarder) setErr(err error) {
	if err == nil {
		return
	}
	s := err.Error()
	f.lastErr.Store(&s)
}

func (f *forwarder) err() string {
	if p := f.lastErr.Load(); p != nil {
		return *p
	}
	return ""
}

// stop releases the local port immediately, without waiting for in-flight
// connections. Freeing the port synchronously is what lets a reconnect
// re-acquire the same local port before anything else can claim it.
func (f *forwarder) stop() {
	f.closeOnce.Do(func() {
		close(f.done)
		_ = f.ln.Close()
	})
}

// Close stops accepting and waits for in-flight connections to finish being
// torn down.
func (f *forwarder) Close() {
	f.stop()
	f.wg.Wait()
}

func isTemporary(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
