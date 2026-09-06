package sshx

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// The case that matters is not a dropped connection but a black-holed one: a
// closed laptop lid or a vanished network leaves the TCP session open as far
// as both ends are concerned, and a keepalive sent into it never comes back.
// The silent server is exactly that — it authenticates and then deliberately
// never answers a global request. Without the deadline in ping this test hangs
// until the test runner kills it.
func TestKeepAliveGivesUpOnAnUnansweredPing(t *testing.T) {
	isolatedHome(t)
	key := generateKey(t, "ed25519")
	server := startServer(t, serverOptions{
		authorized: signerFor(t, key).PublicKey(),
		silent:     true,
	})

	client, err := dialServer(t, server, Overrides{}, Options{
		AuthSock:        startTestAgent(t, key).path,
		KnownHostsFiles: []string{writeKnownHosts(t, server.addr(), server.hostKey())},
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	started := time.Now()
	err = client.KeepAlive(t.Context(), 10*time.Millisecond, 150*time.Millisecond)
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("KeepAlive returned nil; an unanswered keepalive must end the connection")
	}
	if !strings.Contains(err.Error(), "no reply") {
		t.Errorf("err = %v, want it to say the keepalive went unanswered", err)
	}
	// Without the deadline this blocks forever; the point of the test is that
	// it comes back promptly so the caller's reconnect loop can run.
	if elapsed > 2*time.Second {
		t.Errorf("took %s to give up", elapsed)
	}
}

// A healthy connection must not be torn down by its own keepalives.
func TestKeepAliveSurvivesAHealthyConnection(t *testing.T) {
	server := startServer(t, serverOptions{noAuth: true})
	client := connectTo(t, server)

	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()

	err := client.KeepAlive(ctx, 20*time.Millisecond, time.Second)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the context deadline — a healthy link must survive its keepalives", err)
	}
}
