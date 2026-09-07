package sshagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/prompt"
)

// payload is what a client asks to have signed. Its content is immaterial —
// what matters is whether it comes back signed.
var payload = []byte("devtun test payload")

func TestSignatureIsRefusedUntilItIsApproved(t *testing.T) {
	h := start(t, Options{})
	client := h.client()

	if _, err := client.Sign(h.key(), payload); err == nil {
		t.Fatal("a signature was produced with nobody approving it")
	}
	if kinds := h.host.events.kinds(); !slices.Contains(kinds, "denied") {
		t.Errorf("no denial was recorded; got %v", kinds)
	}
	if n := h.host.events.count("signed"); n != 0 {
		t.Errorf("recorded %d signatures for a refused request", n)
	}

	h.prompter.answer(prompt.ChoiceAllowSecretSession)
	signature, err := client.Sign(h.key(), payload)
	if err != nil {
		t.Fatalf("signing after approval: %v", err)
	}
	if err := h.key().Verify(payload, signature); err != nil {
		t.Fatalf("the agent's signature does not verify: %v", err)
	}

	// A session grant lives on the Service, so a second connection — which is
	// what every `git push` opens — must not ask again. This is the difference
	// between a service that survives an afternoon and one that gets switched
	// off.
	if _, err := h.client().Sign(h.key(), payload); err != nil {
		t.Fatalf("signing under a live grant: %v", err)
	}
	if asked := h.prompter.count(); asked != 2 {
		t.Errorf("the human was asked %d times, want 2 (one refused, one granted)", asked)
	}
}

// TestMutationIsRefusedWithoutConsultingPolicy is the invariant that these
// operations are not policy decisions at all. The service is set up so that
// policy would allow everything and the human would say yes to anything; every
// one of them must still be refused, and nobody must be asked.
func TestMutationIsRefusedWithoutConsultingPolicy(t *testing.T) {
	prompter := &scriptedPrompter{choice: prompt.ChoiceAllowHostSession}
	h := start(t, Options{
		Rules:    []authz.Rule{{Host: authz.HostWildcard, Subject: authz.HostWildcard, Action: authz.ActionAllow}},
		Prompter: prompter,
	})
	client := h.client()

	intruder := intruderKey(t)
	operations := map[string]func() error{
		"add":       func() error { return client.Add(agent.AddedKey{PrivateKey: intruder}) },
		"remove":    func() error { return client.Remove(h.key()) },
		"removeAll": client.RemoveAll,
		"lock":      func() error { return client.Lock([]byte("hunter2")) },
		"unlock":    func() error { return client.Unlock([]byte("hunter2")) },
		"signers": func() error {
			_, err := h.gate().Signers()
			return err
		},
	}
	for name, run := range operations {
		if err := run(); err == nil {
			t.Errorf("%s was allowed to change the agent", name)
		}
	}

	if n := h.host.events.count("refused"); n != len(operations) {
		t.Errorf("recorded %d refusals, want %d: %v", n, len(operations), h.host.events.kinds())
	}
	if refusal := h.host.events.find(t, "refused"); refusal.Level != 2 { // event.Warn
		t.Errorf("a refused mutation was recorded at level %v, want warn", refusal.Level)
	}
	if asked := prompter.count(); asked != 0 {
		t.Errorf("the human was asked %d times about an operation that is never allowed", asked)
	}

	// The agent itself must be untouched: the key is still there, and nothing
	// new was added.
	keys, err := h.ring.List()
	if err != nil {
		t.Fatalf("listing the keyring: %v", err)
	}
	if len(keys) != 1 || !slices.Equal(keys[0].Marshal(), h.key().Marshal()) {
		t.Fatalf("the keyring holds %d keys, want only the original one", len(keys))
	}
}

// intruderKey is a key a remote box would try to load into your agent.
func intruderKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating an intruder key: %v", err)
	}
	return private
}

func TestListIsAllowedAndRecorded(t *testing.T) {
	h := start(t, Options{})

	keys, err := h.client().List()
	if err != nil {
		t.Fatalf("listing keys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	listed := h.host.events.find(t, "listed")
	if listed.Level != 1 { // event.Info
		t.Errorf("a listing was recorded at level %v, want info", listed.Level)
	}
	if !strings.Contains(listed.Text, "bedev") {
		t.Errorf("the listing event does not say who listed: %q", listed.Text)
	}
}

// TestDenyRuleBeatsALiveGrant exercises the authz invariant through this
// service, and with it the thing that makes rules writable at all: the subject
// has to be matchable by a glob the user would actually type.
func TestDenyRuleBeatsALiveGrant(t *testing.T) {
	hostKey := newHostKey(t)
	knownHosts := writeKnownHosts(t, map[string]ssh.PublicKey{"github.com": hostKey.PublicKey()})
	prompter := &scriptedPrompter{choice: prompt.ChoiceAllowHostSession}
	h := start(t, Options{
		Rules:      []authz.Rule{{Host: authz.HostWildcard, Subject: "** → github.com", Action: authz.ActionDeny}},
		KnownHosts: []string{knownHosts},
		Prompter:   prompter,
	})

	client := h.client()
	if _, err := client.Extension(sessionBindExtension, bindTo(t, hostKey, false)); err != nil {
		t.Fatalf("binding the session: %v", err)
	}

	// A grant planted as if it had been given before the deny rule existed. A
	// rule added to block something must not be undoable by having clicked
	// through a prompt earlier.
	subject := subjectFor(h.key(), destination{hostKey: hostKey.PublicKey(), name: "github.com"})
	h.svc.gate.Store().GrantSession(h.host.Label(), subject)

	if _, err := client.Sign(h.key(), payload); err == nil {
		t.Fatal("a denied subject was signed because a grant was live")
	}
	denied := h.host.events.find(t, "denied")
	if !strings.Contains(denied.Text, "denied by rule") {
		t.Errorf("the denial does not name the rule: %q", denied.Text)
	}
	if asked := prompter.count(); asked != 0 {
		t.Errorf("the human was asked %d times about a denied subject", asked)
	}
}

func TestSessionBindNamesTheDestination(t *testing.T) {
	hostKey := newHostKey(t)
	knownHosts := writeKnownHosts(t, map[string]ssh.PublicKey{"github.com": hostKey.PublicKey()})
	h := start(t, Options{
		KnownHosts: []string{knownHosts},
		Prompter:   &scriptedPrompter{choice: prompt.ChoiceAllowOnce},
	})

	client := h.client()
	if _, err := client.Extension(sessionBindExtension, bindTo(t, hostKey, false)); err != nil {
		t.Fatalf("binding the session: %v", err)
	}
	if _, err := client.Sign(h.key(), payload); err != nil {
		t.Fatalf("signing: %v", err)
	}

	want := ssh.FingerprintSHA256(h.key()) + " → github.com"
	if got := h.prompter.lastSubject(t); !strings.HasSuffix(got, want) {
		t.Errorf("the human was asked about %q, want it to end in %q", got, want)
	}
	if !strings.HasPrefix(h.prompter.lastSubject(t), h.key().Type()+" ") {
		t.Errorf("the subject does not lead with the key type: %q", h.prompter.lastSubject(t))
	}
}

func TestUnnamedDestinationFallsBackToItsFingerprint(t *testing.T) {
	hostKey := newHostKey(t)
	h := start(t, Options{Prompter: &scriptedPrompter{choice: prompt.ChoiceAllowOnce}})

	client := h.client()
	if _, err := client.Extension(sessionBindExtension, bindTo(t, hostKey, false)); err != nil {
		t.Fatalf("binding the session: %v", err)
	}
	if _, err := client.Sign(h.key(), payload); err != nil {
		t.Fatalf("signing: %v", err)
	}

	want := " → " + ssh.FingerprintSHA256(hostKey.PublicKey())
	if got := h.prompter.lastSubject(t); !strings.HasSuffix(got, want) {
		t.Errorf("the human was asked about %q, want it to end in %q", got, want)
	}
}

// TestWithoutASessionBindTheDestinationIsUnknown covers the older-ssh case. The
// subject must say the destination is unknown rather than quietly omitting it,
// or a rule written for one destination would match a signature going anywhere.
func TestWithoutASessionBindTheDestinationIsUnknown(t *testing.T) {
	h := start(t, Options{Prompter: &scriptedPrompter{choice: prompt.ChoiceAllowOnce}})

	if _, err := h.client().Sign(h.key(), payload); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if got := h.prompter.lastSubject(t); !strings.HasSuffix(got, " → "+unknownDestination) {
		t.Errorf("the human was asked about %q, want it to end in %q", got, " → "+unknownDestination)
	}
}

// TestForgedSessionBindIsIgnored is the reason the bind signature is checked at
// all. A process on the dev box that could name any host key it liked would be
// able to spend a grant given for github.com on a signature going elsewhere.
func TestForgedSessionBindIsIgnored(t *testing.T) {
	real := newHostKey(t)
	other := newHostKey(t)
	knownHosts := writeKnownHosts(t, map[string]ssh.PublicKey{"github.com": real.PublicKey()})
	h := start(t, Options{
		KnownHosts: []string{knownHosts},
		Prompter:   &scriptedPrompter{choice: prompt.ChoiceAllowOnce},
	})

	client := h.client()
	// Bind honestly first, so the test also proves a forged bind drops the
	// binding it replaces rather than leaving the previous one standing.
	if _, err := client.Extension(sessionBindExtension, bindTo(t, real, false)); err != nil {
		t.Fatalf("binding the session: %v", err)
	}
	if _, err := client.Extension(sessionBindExtension, forgedBind(t, real.PublicKey(), other)); err == nil {
		t.Fatal("a session-bind signed by the wrong key was accepted")
	}
	if _, err := client.Sign(h.key(), payload); err != nil {
		t.Fatalf("signing: %v", err)
	}

	if got := h.prompter.lastSubject(t); !strings.HasSuffix(got, " → "+unknownDestination) {
		t.Errorf("the human was asked about %q, want the destination to be unknown", got)
	}
	if n := h.host.events.count("unbound"); n != 1 {
		t.Errorf("recorded %d unbound events, want 1: %v", n, h.host.events.kinds())
	}
}

func TestOtherExtensionsAreRefused(t *testing.T) {
	h := start(t, Options{})

	if _, err := h.client().Extension("restrict-destination-v00@openssh.com", []byte("anything")); err == nil {
		t.Fatal("an unimplemented extension was passed through to the agent")
	}
	if n := h.host.events.count("refused"); n != 1 {
		t.Errorf("recorded %d refusals, want 1: %v", n, h.host.events.kinds())
	}
}

// TestALateAnswerIsNotAnApproval covers the belt-and-braces deadline check. The
// prompter here answers "yes" after the timeout has already passed, which is
// what a human reaching the dialog a moment too late looks like; the request it
// was answering is gone, and an `ssh` client that has already given up must not
// have signed anything.
func TestALateAnswerIsNotAnApproval(t *testing.T) {
	prompter := &scriptedPrompter{choice: prompt.ChoiceAllowHostSession, delay: 200 * time.Millisecond}
	h := start(t, Options{PromptTimeout: 20 * time.Millisecond, Prompter: prompter})

	if _, err := h.client().Sign(h.key(), payload); err == nil {
		t.Fatal("a signature was produced by an answer that arrived after the deadline")
	}
	denied := h.host.events.find(t, "denied")
	if !strings.Contains(denied.Text, "no answer within") {
		t.Errorf("the denial does not blame the timeout: %q", denied.Text)
	}
	if grants := h.svc.Grants(); len(grants) != 0 {
		t.Errorf("a late answer left %d grants behind", len(grants))
	}
}

// TestGrantsSurviveAReconnect is the state-lives-on-the-Service rule. A laptop
// sleeps; being re-asked to approve every key on every reconnect is how the
// approval stops being read.
func TestGrantsSurviveAReconnect(t *testing.T) {
	h := start(t, Options{Prompter: &scriptedPrompter{choice: prompt.ChoiceAllowSecretSession}})

	if _, err := h.client().Sign(h.key(), payload); err != nil {
		t.Fatalf("signing: %v", err)
	}

	// A reconnect is Close then Attach with a fresh Host, never a special case
	// inside the service.
	instance, err := h.svc.Attach(t.Context(), h.host)
	if err != nil {
		t.Fatalf("attaching: %v", err)
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	reconnected := newFakeHost(h.host.Label())
	if _, err := h.svc.Attach(t.Context(), reconnected); err != nil {
		t.Fatalf("reattaching: %v", err)
	}

	if _, err := h.client().Sign(h.key(), payload); err != nil {
		t.Fatalf("signing after a reconnect: %v", err)
	}
	if asked := h.prompter.count(); asked != 1 {
		t.Errorf("the human was asked %d times across a reconnect, want 1", asked)
	}
	if n := reconnected.events.count("signed"); n != 1 {
		t.Errorf("the reconnected host recorded %d signatures, want 1: %v", n, reconnected.events.kinds())
	}
}

// TestConcurrentConnectionsKeepTheirOwnDestination is the isolation property
// that makes the destination worth anything. Two `ssh` clients running at once
// is the ordinary case, and a binding leaking between them would put one
// destination's name on the other's signature.
func TestConcurrentConnectionsKeepTheirOwnDestination(t *testing.T) {
	alpha, beta := newHostKey(t), newHostKey(t)
	knownHosts := writeKnownHosts(t, map[string]ssh.PublicKey{
		"alpha.example": alpha.PublicKey(),
		"beta.example":  beta.PublicKey(),
	})
	h := start(t, Options{
		KnownHosts: []string{knownHosts},
		Prompter:   &scriptedPrompter{choice: prompt.ChoiceAllowOnce},
	})

	first, second := h.client(), h.client()
	if _, err := first.Extension(sessionBindExtension, bindTo(t, alpha, false)); err != nil {
		t.Fatalf("binding the first session: %v", err)
	}
	if _, err := second.Extension(sessionBindExtension, bindTo(t, beta, false)); err != nil {
		t.Fatalf("binding the second session: %v", err)
	}

	var signing sync.WaitGroup
	for _, client := range []agent.ExtendedAgent{first, second} {
		signing.Add(1)
		go func() {
			defer signing.Done()
			if _, err := client.Sign(h.key(), payload); err != nil {
				t.Errorf("signing: %v", err)
			}
		}()
	}
	signing.Wait()

	got := h.prompter.subjects()
	slices.Sort(got)
	want := []string{
		subjectFor(h.key(), destination{hostKey: alpha.PublicKey(), name: "alpha.example"}),
		subjectFor(h.key(), destination{hostKey: beta.PublicKey(), name: "beta.example"}),
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("the human was asked about\n%v\nwant\n%v", got, want)
	}
}

func TestSetupLineNamesTheSocketBesideTheControlSocket(t *testing.T) {
	h := start(t, Options{})

	want := []string{`export SSH_AUTH_SOCK="/run/user/1000/devtun-agent.sock"`}
	if got := h.svc.SetupLines(h.host); !slices.Equal(got, want) {
		t.Errorf("SetupLines returned %q, want %q", got, want)
	}
}

func TestProbeWithoutAnAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")

	support := New(Options{}).Probe(t.Context(), newFakeHost("bedev"))
	if support.OK {
		t.Fatal("probing succeeded with no agent to forward")
	}
	if support.Reason != "no SSH agent to forward (SSH_AUTH_SOCK is unset)" {
		t.Errorf("the probe explained itself as %q", support.Reason)
	}
}

func TestProbeReportsTheLoadedKeys(t *testing.T) {
	ring := agent.NewKeyring()
	addKey(t, ring)

	support := New(Options{Dial: serveKeyring(t, ring)}).Probe(t.Context(), newFakeHost("bedev"))
	if !support.OK {
		t.Fatalf("probing failed with a working agent: %s", support.Reason)
	}
	if support.Detail != "1 key loaded" {
		t.Errorf("the probe reported %q", support.Detail)
	}
}
