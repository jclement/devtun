package sshx

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/buildinfo"
)

func TestParseJumpChain(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"none", nil},
		{"NONE", nil},
		{"bastion", []string{"bastion"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b ", []string{"a", "b"}},
		{",,", nil},
	}
	for _, tt := range tests {
		if got := parseJumpChain(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseJumpChain(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// Each hop is a full SSH connection whose transport is a channel on the
// previous one, and Close has to take the whole chain with it: a jump left
// open behind a reconnecting session accumulates one connection per hiccup.
func TestDialThroughAProxyJumpChain(t *testing.T) {
	isolatedHome(t)

	target := startServer(t, serverOptions{noAuth: true})
	target.respond = func(string) string { return "on the far side\n" }
	jump := startServer(t, serverOptions{noAuth: true})
	jump.echo = target.addr()

	d, err := Resolve(target.addr(), nil, Overrides{User: "tester", ProxyJump: jump.addr()})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	client, err := Dial(t.Context(), d, Options{HostKeyMode: HostKeyNone})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	got, err := client.Output(t.Context(), "hello\n")
	if err != nil {
		t.Fatalf("Output over the jump: %v", err)
	}
	if got != "on the far side\n" {
		t.Errorf("Output = %q, want the target server's answer", got)
	}
	if forwards := jump.forwardTargets(); len(forwards) != 1 {
		t.Errorf("the jump host saw %v forwards, want exactly the one to the target", forwards)
	}

	client.Close()
	waitFor(t, "both connections to close", func() bool {
		return target.liveConnections() == 0 && jump.liveConnections() == 0
	})
}

// The banner is how a server's logs say which of your tools connected, so it
// carries this build rather than a bare library default.
func TestDialAnnouncesThisBuild(t *testing.T) {
	server := startServer(t, serverOptions{noAuth: true})
	connectTo(t, server)

	if got := server.awaitBanner(t); got != buildinfo.UserAgent() {
		t.Errorf("client version = %q, want %q", got, buildinfo.UserAgent())
	}

	custom := startServer(t, serverOptions{noAuth: true})
	isolatedHome(t)
	if _, err := dialServer(t, custom, Overrides{}, Options{
		HostKeyMode:   HostKeyNone,
		ClientVersion: "SSH-2.0-something_else",
	}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if got := custom.awaitBanner(t); got != "SSH-2.0-something_else" {
		t.Errorf("client version = %q, want the override", got)
	}
}

func TestDialReportsAnUnreachableHost(t *testing.T) {
	isolatedHome(t)
	d, err := Resolve(deadAddress(t), nil, Overrides{User: "tester"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	_, err = Dial(t.Context(), d, Options{HostKeyMode: HostKeyNone, ConnectTimeout: 2 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "connecting to") {
		t.Errorf("Dial = %v, want a connection error naming the destination", err)
	}
}

// With nothing to authenticate with, the error has to say so — otherwise it
// arrives as a bare "unable to authenticate" and reads like a rejected key.
func TestDialWithoutAnyCredentials(t *testing.T) {
	isolatedHome(t)
	server := startServer(t, serverOptions{authorized: newPublicKey(t, "ed25519")})

	_, err := dialServer(t, server, Overrides{}, Options{
		HostKeyMode:    HostKeyNone,
		ConnectTimeout: 3 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "no usable SSH keys") {
		t.Errorf("Dial = %v, want an error saying there were no keys to offer", err)
	}
}

// --wait exists for a dev box that is still booting: the first refusal is the
// expected state, not the answer.
func TestDialWaitRetriesTheInitialConnection(t *testing.T) {
	isolatedHome(t)
	d, err := Resolve(deadAddress(t), nil, Overrides{User: "tester"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	t.Run("without wait it gives up at once", func(t *testing.T) {
		prompter := &stubPrompter{}
		started := time.Now()
		if _, err := Dial(t.Context(), d, Options{HostKeyMode: HostKeyNone, Prompter: prompter}); err == nil {
			t.Fatal("Dial should have failed")
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Errorf("took %s to report a refused connection", elapsed)
		}
		if len(prompter.notices) != 0 {
			t.Errorf("nothing should be said about retrying: %v", prompter.notices)
		}
	})

	t.Run("with wait it keeps trying until the context ends", func(t *testing.T) {
		prompter := &stubPrompter{}
		ctx, cancel := context.WithTimeout(t.Context(), 1200*time.Millisecond)
		defer cancel()

		started := time.Now()
		if _, err := Dial(ctx, d, Options{HostKeyMode: HostKeyNone, Prompter: prompter, Wait: true}); err == nil {
			t.Fatal("Dial should have failed once the context ended")
		}
		if elapsed := time.Since(started); elapsed < time.Second {
			t.Errorf("gave up after %s; --wait should have retried", elapsed)
		}
		if len(prompter.notices) == 0 {
			t.Error("a retry the user is waiting through has to be said out loud")
		}
	})
}

// deadAddress binds a port and immediately releases it, so nothing is
// listening there.
func deadAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

// waitFor polls until condition holds, failing the test if it never does.
func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("timed out waiting for %s", what)
}
