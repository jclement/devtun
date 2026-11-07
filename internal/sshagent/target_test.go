package sshagent

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/prompt"
)

// boundToGitHub starts a service that knows hostKey as github.com, with a
// session grant already given for logins there, and returns a client bound to
// a genuine github.com session plus that session's identifier.
//
// It is the attacker's best starting position: a real, verifiable bind for an
// approved destination, which is exactly what a compromised box sees whenever
// the user runs `git fetch`.
func boundToGitHub(t *testing.T, prompter *scriptedPrompter) (*harness, ssh.Signer, []byte, func([]byte) error) {
	t.Helper()
	hostKey := newHostKey(t)
	knownHosts := writeKnownHosts(t, map[string]ssh.PublicKey{"github.com": hostKey.PublicKey()})
	h := start(t, Options{KnownHosts: []string{knownHosts}, Prompter: prompter})

	client := h.client()
	bind, sessionID := bindSession(t, hostKey, false)
	if _, err := client.Extension(sessionBindExtension, bind); err != nil {
		t.Fatalf("binding the session: %v", err)
	}
	granted := subjectFor(h.key(), target{dest: destination{hostKey: hostKey.PublicKey(), name: "github.com"}})
	h.svc.gate.Store().GrantSession(h.host.Label(), granted)

	sign := func(data []byte) error {
		_, err := client.Sign(h.key(), data)
		return err
	}
	return h, hostKey, sessionID, sign
}

// TestALoginForTheBoundSessionRidesTheGrant is the ordinary case the binding
// must not break: the login the bind was for is signed under the grant, with
// nobody asked.
func TestALoginForTheBoundSessionRidesTheGrant(t *testing.T) {
	prompter := &scriptedPrompter{}
	h, hostKey, sessionID, sign := boundToGitHub(t, prompter)

	if err := sign(login(h.key(), sessionID)); err != nil {
		t.Fatalf("a login for the bound session was refused: %v", err)
	}
	if err := sign(hostBoundLogin(h.key(), sessionID, hostKey.PublicKey())); err != nil {
		t.Fatalf("a hostbound login for the bound session was refused: %v", err)
	}
	if n := prompter.count(); n != 0 {
		t.Errorf("the human was asked %d times about logins a grant covers", n)
	}
}

// TestALoginForAnotherSessionIsRefused is the P1 this file exists for: a
// genuine bind for github.com, then a login for some other session. It must be
// refused outright — not signed under the github.com grant, and not offered to
// the human either, because there is no honest subject to ask about.
func TestALoginForAnotherSessionIsRefused(t *testing.T) {
	prompter := &scriptedPrompter{choice: prompt.ChoiceAllowHostSession}
	h, _, _, sign := boundToGitHub(t, prompter)

	if err := sign(login(h.key(), newSessionID(t))); err == nil {
		t.Fatal("a login for a different session was signed under the github.com grant")
	}
	if n := prompter.count(); n != 0 {
		t.Errorf("the human was asked %d times about a login the binding contradicts", n)
	}
	denied := h.host.events.find(t, "denied")
	if !strings.Contains(denied.Text, "different SSH session") {
		t.Errorf("the denial does not say why: %q", denied.Text)
	}
	if n := h.host.events.count("signed"); n != 0 {
		t.Errorf("recorded %d signatures", n)
	}
}

// TestAHostBoundLoginForAnotherHostIsRefused covers the hostbound method, whose
// signed data names the destination's host key: it has to be the bound one.
func TestAHostBoundLoginForAnotherHostIsRefused(t *testing.T) {
	prompter := &scriptedPrompter{choice: prompt.ChoiceAllowHostSession}
	h, _, sessionID, sign := boundToGitHub(t, prompter)

	if err := sign(hostBoundLogin(h.key(), sessionID, newHostKey(t).PublicKey())); err == nil {
		t.Fatal("a hostbound login naming another host key was signed")
	}
	if n := prompter.count(); n != 0 {
		t.Errorf("the human was asked %d times", n)
	}
}

// TestALoginNamingAnotherKeyIsRefused: the login must be for the key asked to
// sign it, as OpenSSH's agent also requires.
func TestALoginNamingAnotherKeyIsRefused(t *testing.T) {
	prompter := &scriptedPrompter{choice: prompt.ChoiceAllowHostSession}
	_, _, sessionID, sign := boundToGitHub(t, prompter)

	if err := sign(login(newHostKey(t).PublicKey(), sessionID)); err == nil {
		t.Fatal("a login naming a different key was signed")
	}
}

// TestAMalformedLoginIsRefused: something that starts like a login is held to
// a login's rules, so it cannot escape the session check by being broken.
func TestAMalformedLoginIsRefused(t *testing.T) {
	prompter := &scriptedPrompter{choice: prompt.ChoiceAllowHostSession}
	h, _, sessionID, sign := boundToGitHub(t, prompter)

	broken := append(login(h.key(), sessionID), 0x00)
	if err := sign(broken); err == nil {
		t.Fatal("a login with trailing data was signed")
	}
	truncated := ssh.Marshal(struct {
		SessionID []byte
		Type      byte
	}{sessionID, msgUserAuthRequest})
	if err := sign(truncated); err == nil {
		t.Fatal("a truncated login was signed")
	}
	if n := prompter.count(); n != 0 {
		t.Errorf("the human was asked %d times", n)
	}
}

// TestArbitraryDataIsItsOwnSubject: bytes that are neither a login nor SSHSIG
// do not ride a destination grant. They are asked about under their own,
// plainly labelled subject.
func TestArbitraryDataIsItsOwnSubject(t *testing.T) {
	prompter := &scriptedPrompter{choice: prompt.ChoiceAllowOnce}
	h, _, _, sign := boundToGitHub(t, prompter)

	if err := sign(payload); err != nil {
		t.Fatalf("signing after the human allowed it: %v", err)
	}
	if n := prompter.count(); n != 1 {
		t.Fatalf("the human was asked %d times, want once: the github.com grant must not cover arbitrary data", n)
	}
	want := subjectFor(h.key(), target{kind: targetArbitrary})
	if got := prompter.lastSubject(t); got != want {
		t.Errorf("asked about %q, want %q", got, want)
	}
	if !strings.HasSuffix(want, " → (arbitrary data)") {
		t.Errorf("the subject format drifted: %q", want)
	}
	request := prompter.lastRequest(t)
	if request.Prefer != prompt.ChoiceDeny {
		t.Errorf("the prompt for arbitrary data starts on %v, want the safe default", request.Prefer)
	}
}

// TestGitSigningIsNamedForItsNamespace: SSHSIG keeps working, and the subject
// says what is being signed, so `* → sshsig:git` is a rule someone can write.
func TestGitSigningIsNamedForItsNamespace(t *testing.T) {
	prompter := &scriptedPrompter{choice: prompt.ChoiceAllowSecretSession}
	h, _, _, sign := boundToGitHub(t, prompter)

	if err := sign(sshsig("git")); err != nil {
		t.Fatalf("git signing was refused: %v", err)
	}
	want := h.key().Type() + " " + ssh.FingerprintSHA256(h.key()) + " → sshsig:git"
	if got := prompter.lastSubject(t); got != want {
		t.Errorf("asked about %q, want %q", got, want)
	}
	// The session grant just given covers the next commit, and only that.
	if err := sign(sshsig("git")); err != nil {
		t.Fatalf("a second git signature: %v", err)
	}
	if n := prompter.count(); n != 1 {
		t.Errorf("asked %d times, want once", n)
	}
	if err := sign(sshsig("file")); err != nil {
		t.Fatalf("file signing: %v", err)
	}
	if n := prompter.count(); n != 2 {
		t.Errorf("a git grant covered another namespace: asked %d times, want 2", n)
	}
}

// TestNamespaceCannotRewriteTheSubject: the namespace is the remote's to
// choose, so one that would need rewriting to fit a subject — a " → ", a slash,
// an escape — is refused rather than cleaned up.
func TestNamespaceCannotRewriteTheSubject(t *testing.T) {
	prompter := &scriptedPrompter{choice: prompt.ChoiceAllowOnce}
	_, _, _, sign := boundToGitHub(t, prompter)

	if err := sign(sshsig("x → github.com/../\x1b[2J")); err == nil {
		t.Fatal("a namespace that does not fit a subject was signed")
	}
	if n := prompter.count(); n != 0 {
		t.Errorf("asked %d times about an unnameable namespace", n)
	}
}

// TestNamespacesThatLookAlikeAreDistinct is the review's P2. Sanitising made
// "release_prod" and "release/prod" one subject, and two long namespaces with
// the same first 64 characters one subject, so approving one approved the
// other while the signature covered whichever was asked for. Each subject now
// names exactly one namespace.
func TestNamespacesThatLookAlikeAreDistinct(t *testing.T) {
	prompter := &scriptedPrompter{choice: prompt.ChoiceAllowSecretSession}
	h, _, _, sign := boundToGitHub(t, prompter)

	if err := sign(sshsig("release_prod")); err != nil {
		t.Fatalf("a plain namespace was refused: %v", err)
	}
	if err := sign(sshsig("release/prod")); err == nil {
		t.Error("release/prod was signed — under release_prod's grant, or as its own subject")
	}

	prefix := strings.Repeat("a", namespaceLimit)
	if err := sign(sshsig(prefix)); err != nil {
		t.Fatalf("a namespace exactly at the limit was refused: %v", err)
	}
	for _, long := range []string{prefix + "-one", prefix + "-two"} {
		if err := sign(sshsig(long)); err == nil {
			t.Errorf("an over-long namespace sharing a prefix was signed: %q", long)
		}
	}
	if n := prompter.count(); n != 2 {
		t.Errorf("asked %d times, want 2 (release_prod and the %d-character name)", n, namespaceLimit)
	}
	if n := h.host.events.count("signed"); n != 2 {
		t.Errorf("recorded %d signatures, want 2", n)
	}

	// A deny for one namespace does not touch a look-alike either.
	if _, err := h.svc.AddRule(authz.Rule{Subject: "* → sshsig:release_prod", Action: authz.ActionDeny}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if err := sign(sshsig("release_prod")); err == nil {
		t.Error("the deny for release_prod did not apply")
	}
	if err := sign(sshsig("release-prod")); err != nil {
		t.Errorf("the deny for release_prod also refused release-prod: %v", err)
	}
}

// TestASecondBindAfterALoginBindIsRefused: a connection bound for its own login
// cannot be re-aimed at another destination.
func TestASecondBindAfterALoginBindIsRefused(t *testing.T) {
	h := start(t, Options{Prompter: &scriptedPrompter{choice: prompt.ChoiceAllowOnce}})

	client := h.client()
	first, firstSession := bindSession(t, newHostKey(t), false)
	if _, err := client.Extension(sessionBindExtension, first); err != nil {
		t.Fatalf("binding: %v", err)
	}
	second, _ := bindSession(t, newHostKey(t), false)
	if _, err := client.Extension(sessionBindExtension, second); err == nil {
		t.Fatal("a second bind replaced a login binding")
	}
	// The first binding stands: its own login still works.
	if _, err := client.Sign(h.key(), login(h.key(), firstSession)); err != nil {
		t.Fatalf("the original binding was lost: %v", err)
	}
}

// TestAForwardedHopsLoginIsUnknownDestinationVia: bound for a host that
// forwards the agent onward, a login for another session is that host's own
// onward hop. It is not refused — OpenSSH allows it too — but it is not the
// bound host either: the destination is unknown, and the prompt says which
// host it came through.
func TestAForwardedHopsLoginIsUnknownDestinationVia(t *testing.T) {
	jump := newHostKey(t)
	knownHosts := writeKnownHosts(t, map[string]ssh.PublicKey{"jump.example": jump.PublicKey()})
	prompter := &scriptedPrompter{choice: prompt.ChoiceAllowOnce}
	h := start(t, Options{KnownHosts: []string{knownHosts}, Prompter: prompter})

	client := h.client()
	bind, _ := bindSession(t, jump, true)
	if _, err := client.Extension(sessionBindExtension, bind); err != nil {
		t.Fatalf("binding: %v", err)
	}
	if _, err := client.Sign(h.key(), login(h.key(), newSessionID(t))); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if got := prompter.lastSubject(t); !strings.HasSuffix(got, " → "+unknownDestination) {
		t.Errorf("asked about %q, want an unknown destination", got)
	}
	var via string
	for _, row := range prompter.lastRequest(t).Rows {
		if row.Label == "via" {
			via = row.Value
		}
	}
	if !strings.Contains(via, "jump.example") {
		t.Errorf("the prompt does not say the login came through jump.example: %q", via)
	}
}

// TestAWildcardDestinationDoesNotAllowArbitraryData: `key → *`, `key → **`,
// `**` and a host-wide grant were written about where a key may log in. None
// of them approves bytes devtun cannot identify — that takes a rule naming
// `(arbitrary data)`. A wildcard deny still refuses them.
func TestAWildcardDestinationDoesNotAllowArbitraryData(t *testing.T) {
	keyPattern := func(h *harness) string { return h.key().Type() + " " + ssh.FingerprintSHA256(h.key()) }

	for _, pattern := range []string{"* → *", "* → **", "**", "KEY → *", "KEY → **"} {
		t.Run(pattern, func(t *testing.T) {
			prompter := &scriptedPrompter{choice: prompt.ChoiceDeny}
			h := start(t, Options{Prompter: prompter})
			subject := strings.Replace(pattern, "KEY", keyPattern(h), 1)
			if _, err := h.svc.AddRule(authz.Rule{Subject: subject, Action: authz.ActionAllow}); err != nil {
				t.Fatalf("AddRule: %v", err)
			}
			if _, err := h.client().Sign(h.key(), sshsig("git")); err != nil {
				t.Fatalf("the wildcard no longer allows git signing: %v", err)
			}
			if _, err := h.client().Sign(h.key(), payload); err == nil {
				t.Fatalf("%q allowed arbitrary data", subject)
			}
			if n := prompter.count(); n != 1 {
				t.Errorf("asked %d times, want once — for the arbitrary data only", n)
			}
		})
	}

	t.Run("host-wide grant", func(t *testing.T) {
		prompter := &scriptedPrompter{choice: prompt.ChoiceDeny}
		h := start(t, Options{Prompter: prompter})
		h.svc.gate.Store().GrantSession(h.host.Label(), authz.HostWildcard)
		if _, err := h.client().Sign(h.key(), payload); err == nil {
			t.Fatal("a host-wide grant allowed arbitrary data")
		}
	})

	t.Run("named literally", func(t *testing.T) {
		h := start(t, Options{Prompter: &scriptedPrompter{choice: prompt.ChoiceDeny}})
		if _, err := h.svc.AddRule(authz.Rule{Subject: "* → (arbitrary data)", Action: authz.ActionAllow}); err != nil {
			t.Fatalf("AddRule: %v", err)
		}
		if _, err := h.client().Sign(h.key(), payload); err != nil {
			t.Fatalf("a rule naming (arbitrary data) did not allow it: %v", err)
		}
	})

	t.Run("wildcard deny still refuses", func(t *testing.T) {
		prompter := &scriptedPrompter{choice: prompt.ChoiceAllowOnce}
		h := start(t, Options{Prompter: prompter})
		if _, err := h.svc.AddRule(authz.Rule{Subject: "* → *", Action: authz.ActionDeny}); err != nil {
			t.Fatalf("AddRule: %v", err)
		}
		if _, err := h.client().Sign(h.key(), payload); err == nil {
			t.Fatal("a * → * deny no longer refuses arbitrary data")
		}
		if n := prompter.count(); n != 0 {
			t.Errorf("asked %d times about a denied subject", n)
		}
	})
}
