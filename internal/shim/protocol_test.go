package shim

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	sent := Hello{V: Version, Service: ServiceOp}
	sent.Caller.User = "jsc"
	sent.Caller.Program = "deploy.sh"

	if err := WriteFrame(&buf, sent); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	var got Hello
	if err := ReadFrame(&buf, &got); err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Service != ServiceOp || got.Caller.Program != "deploy.sh" {
		t.Errorf("frame did not survive the round trip: %+v", got)
	}
}

// A clean hangup must stay distinguishable from a failure: callers use
// errors.Is(err, io.EOF) to tell "the peer went away" from "something broke".
func TestReadFrameReturnsBareEOF(t *testing.T) {
	err := ReadFrame(bytes.NewReader(nil), &Hello{})
	if !errors.Is(err, io.EOF) {
		t.Fatalf("want io.EOF, got %v", err)
	}
	if err != io.EOF { //nolint:errorlint // the point of the test is that it is unwrapped
		t.Errorf("io.EOF must not be wrapped, got %#v", err)
	}
}

func TestReadFrameRejectsAnAbsurdLength(t *testing.T) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], MaxFrameBytes+1)

	err := ReadFrame(bytes.NewReader(header[:]), &Hello{})
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge, got %v", err)
	}
}

func TestWriteFrameRejectsAnOversizeBody(t *testing.T) {
	huge := Hello{Service: strings.Repeat("x", MaxFrameBytes+1)}
	if err := WriteFrame(io.Discard, huge); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge, got %v", err)
	}
}

func TestTruncatedBodyIsAnError(t *testing.T) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 64)

	err := ReadFrame(bytes.NewReader(header[:]), &Hello{})
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("a truncated body should be a real error, got %v", err)
	}
}
