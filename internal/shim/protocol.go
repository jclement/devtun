// Package shim is the wire between a devtun session and the small binary that
// lives on the remote dev box.
//
// It holds both halves. The framing and the Hello envelope are shared; Client
// is the remote side, compiled into the same binary and reached by argv[0]
// dispatch, so `op` and `xdg-open` on the dev box are symlinks to one file.
//
// The envelope exists because devtun multiplexes. opproxy had one socket that
// only ever carried `op` calls, so its request type could be an `op` invocation
// with no room for anything else. devtun has one socket carrying every service,
// so a connection announces what it is before it says anything else, and the
// session routes on that. Each service keeps its own message types after the
// Hello, which is what lets a future service want a long-lived stream without
// renegotiating anything here.
package shim

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/jclement/devtun/internal/service"
)

const (
	// Version is the envelope version. It is checked for equality, not
	// compatibility: a shim and a session that disagree should be made to
	// agree, and the session re-uploads the shim automatically, so there is
	// no long tail of old versions to support.
	Version = 1
	// MaxFrameBytes caps a frame so a hostile remote cannot make the
	// workstation allocate without bound.
	MaxFrameBytes = 8 << 20
)

// ErrFrameTooLarge is returned rather than allocating an absurd buffer.
var ErrFrameTooLarge = errors.New("frame exceeds the maximum size")

// Hello is the first frame on every connection. It names the service the
// connection is for and describes the caller.
type Hello struct {
	V       int    `json:"v"`
	Service string `json:"svc"`
	// Caller is self-reported by a process on a box devtun treats as only
	// semi-trusted. It is shown to the human, because "deploy.sh in
	// ~/projects/api wants this" is what makes an approval decision possible,
	// and it never reaches a policy decision. Those are made from the SSH
	// destination, which is authenticated.
	Caller service.Caller `json:"caller"`
}

// Service identifiers carried in a Hello.
//
// These are the services' own Meta().ID values, not names of their own. The
// session registers socket handlers under the service id, so a second spelling
// here would be a mapping table that exists only to be got wrong — and its
// failure mode is silent: a connection routed nowhere.
const (
	ServiceOp   = "1password"
	ServiceOpen = "browser"
)

// WriteFrame writes v as a length-prefixed JSON frame.
func WriteFrame(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encoding frame: %w", err)
	}
	if len(body) > MaxFrameBytes {
		return ErrFrameTooLarge
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("writing frame header: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("writing frame body: %w", err)
	}
	return nil
}

// ReadFrame reads one length-prefixed JSON frame into v.
//
// io.EOF is returned unwrapped: callers distinguish "the peer hung up
// cleanly" from a real failure, and wrapping it would break errors.Is at every
// call site that matters.
func ReadFrame(r io.Reader, v any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return io.EOF
		}
		return fmt.Errorf("reading frame header: %w", err)
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > MaxFrameBytes {
		return ErrFrameTooLarge
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		// The header promised size bytes, so anything short of that is a
		// truncated frame, not a clean hangup. Translating it matters: a
		// caller testing errors.Is(err, io.EOF) to mean "the peer finished"
		// would otherwise mistake a half-delivered frame for one.
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("reading frame body: %w", err)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("decoding frame: %w", err)
	}
	return nil
}
