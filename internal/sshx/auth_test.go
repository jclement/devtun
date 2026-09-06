package sshx

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// The headline case: a key that exists only inside an agent authenticates a
// real connection, with no identity file anywhere. A hardware token never
// exposes a private key file, so this is the only path it has.
func TestDialAuthenticatesWithAnAgentOnlyKey(t *testing.T) {
	isolatedHome(t)
	key := generateKey(t, "ed25519")
	server := startServer(t, serverOptions{authorized: signerFor(t, key).PublicKey()})

	client, err := dialServer(t, server, Overrides{}, Options{
		AuthSock:        startTestAgent(t, key).path,
		KnownHostsFiles: []string{writeKnownHosts(t, server.addr(), server.hostKey())},
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if client.Dest().User != "tester" {
		t.Errorf("User = %q, want tester", client.Dest().User)
	}
}

// A smartcard behind gpg-agent typically presents an RSA key. Modern servers
// refuse the SHA-1 ssh-rsa algorithm, so the signature has to be requested from
// the agent as rsa-sha2-256 or rsa-sha2-512; this server accepts nothing else.
func TestDialUsesRSASHA2WithAnAgentKey(t *testing.T) {
	isolatedHome(t)
	key := generateKey(t, "rsa")
	server := startServer(t, serverOptions{
		authorized:       signerFor(t, key).PublicKey(),
		pubKeyAlgorithms: []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512},
	})

	if _, err := dialServer(t, server, Overrides{}, Options{
		AuthSock:        startTestAgent(t, key).path,
		KnownHostsFiles: []string{writeKnownHosts(t, server.addr(), server.hostKey())},
	}); err != nil {
		t.Fatalf("Dial with an RSA agent key: %v", err)
	}
}

// An identity file must still be tried when the agent holds a key the server
// rejects. Both are `publickey`, and x/crypto/ssh never attempts a method name
// twice — so they have to be offered by one method, or the file key is
// silently unreachable and the failure is indistinguishable from a bad key.
func TestDialFallsBackFromAgentKeyToIdentityFile(t *testing.T) {
	isolatedHome(t)
	agentOnly := generateKey(t, "ed25519")
	keyPath, filePublic := writeKeyPair(t, t.TempDir(), "id_ed25519")

	server := startServer(t, serverOptions{authorized: filePublic})

	if _, err := dialServer(t, server,
		Overrides{IdentityFiles: []string{keyPath}},
		Options{
			AuthSock:        startTestAgent(t, agentOnly).path,
			KnownHostsFiles: []string{writeKnownHosts(t, server.addr(), server.hostKey())},
		}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
}

// devtun reconnects whenever the network hiccups, so an agent connection left
// open per attempt would exhaust the process's file descriptors over a long
// session.
func TestHandshakeDoesNotLeakAgentConnections(t *testing.T) {
	isolatedHome(t)
	key := generateKey(t, "ed25519")
	server := startServer(t, serverOptions{authorized: signerFor(t, key).PublicKey()})
	fakeAgent := startTestAgent(t, key)
	knownHosts := writeKnownHosts(t, server.addr(), server.hostKey())

	for i := range 5 {
		client, err := dialServer(t, server, Overrides{}, Options{
			AuthSock:        fakeAgent.path,
			KnownHostsFiles: []string{knownHosts},
		})
		if err != nil {
			t.Fatalf("Dial attempt %d: %v", i, err)
		}
		client.Close()
	}

	// The agent's serving goroutines notice the close asynchronously.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && fakeAgent.openConnections() > 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if open := fakeAgent.openConnections(); open != 0 {
		t.Errorf("%d agent connections still open after 5 handshakes", open)
	}
}

// A key held in an agent — a YubiKey, or one whose passphrase you already
// typed — is far likelier to be the live credential than a forgotten id_rsa in
// ~/.ssh. Since every refused key spends one of the server's attempts, the
// agent has to go first, or a single-attempt server rejects a working setup.
func TestAgentIsOfferedBeforeDiscoveredKeys(t *testing.T) {
	isolatedHome(t)
	writeKeyPair(t, filepath.Join(os.Getenv("HOME"), ".ssh"), "id_ed25519") // a stale key on disk

	agentKey := generateKey(t, "ed25519")
	agentPublic := signerFor(t, agentKey).PublicKey()
	server := startServer(t, serverOptions{authorized: agentPublic, maxAuthTries: 1})

	if _, err := dialServer(t, server, Overrides{}, Options{
		AuthSock:    startTestAgent(t, agentKey).path,
		HostKeyMode: HostKeyNone,
	}); err != nil {
		t.Fatalf("Dial = %v, want the agent key to be offered first", err)
	}

	offered := server.offeredKeys()
	if len(offered) == 0 {
		t.Fatal("no keys were offered")
	}
	if offered[0] != string(agentPublic.Marshal()) {
		t.Error("the first key offered was not the agent's")
	}
}

// Naming a key in ssh_config is a statement about which one to use, so it goes
// first even when an agent is running. (Naming one with -i goes further and
// suppresses the agent entirely; see TestIdentitiesOnlySuppressesTheAgent.)
func TestNamedIdentityIsOfferedBeforeTheAgent(t *testing.T) {
	isolatedHome(t)
	named, namedPublic := writeKeyPair(t, t.TempDir(), "named")
	agentKey := generateKey(t, "ed25519")

	server := startServer(t, serverOptions{authorized: namedPublic, maxAuthTries: 1})
	cfg := configFrom(t, "Host *\n  IdentityFile "+named+"\n")
	d, err := Resolve(server.addr(), cfg, Overrides{User: "tester"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.IdentitiesOnly {
		t.Fatal("IdentityFile in ssh_config must not imply IdentitiesOnly")
	}

	client, err := Dial(t.Context(), d, Options{
		AuthSock:    startTestAgent(t, agentKey).path,
		HostKeyMode: HostKeyNone,
	})
	if err != nil {
		t.Fatalf("Dial = %v, want the named key to be offered first", err)
	}
	defer client.Close()

	offered := server.offeredKeys()
	if len(offered) == 0 || offered[0] != string(namedPublic.Marshal()) {
		t.Error("the first key offered was not the one named in ssh_config")
	}
}

// A default key the agent already holds must not be offered twice: the second
// attempt is wasted against the server's budget.
func TestDiscoveredKeysAlreadyInTheAgentAreOfferedOnce(t *testing.T) {
	home := isolatedHome(t)
	path, public := writeKeyPair(t, filepath.Join(home, ".ssh"), "id_ed25519")

	// Accept nothing, so every available key is offered and counted.
	server := startServer(t, serverOptions{maxAuthTries: 10})
	if _, err := dialServer(t, server, Overrides{}, Options{
		AuthSock:    agentHolding(t, path).path,
		HostKeyMode: HostKeyNone,
	}); err == nil {
		t.Fatal("Dial should have failed against a server accepting nothing")
	}

	var count int
	for _, k := range server.offeredKeys() {
		if k == string(public.Marshal()) {
			count++
		}
	}
	if count != 1 {
		t.Errorf("the key was offered %d times, want once", count)
	}
}

func TestIdentitiesOnlySuppressesTheAgent(t *testing.T) {
	isolatedHome(t)
	named, _ := writeKeyPair(t, t.TempDir(), "named")
	agentKey := generateKey(t, "ed25519")
	agentPublic := signerFor(t, agentKey).PublicKey()

	// The server accepts only the agent's key, which must never be offered.
	server := startServer(t, serverOptions{authorized: agentPublic, maxAuthTries: 10})
	if _, err := dialServer(t, server,
		Overrides{IdentityFiles: []string{named}},
		Options{
			AuthSock:    startTestAgent(t, agentKey).path,
			HostKeyMode: HostKeyNone,
		}); err == nil {
		t.Fatal("Dial should have failed with the agent suppressed")
	}

	for _, k := range server.offeredKeys() {
		if k == string(agentPublic.Marshal()) {
			t.Error("an agent key was offered despite IdentitiesOnly")
		}
	}
}

// An encrypted key is offered to the server before its passphrase is asked
// for, so a key the server will not accept never costs the user a prompt.
func TestEncryptedKeyIsUnlockedOnlyWhenTheServerAcceptsIt(t *testing.T) {
	isolatedHome(t)
	dir := t.TempDir()
	encrypted, encryptedPublic := writeEncryptedKeyPair(t, dir, "id_encrypted", "hunter2")

	t.Run("refused key is never unlocked", func(t *testing.T) {
		server := startServer(t, serverOptions{authorized: newPublicKey(t, "ed25519")})
		prompter := &stubPrompter{secret: "hunter2"}
		if _, err := dialServer(t, server,
			Overrides{IdentityFiles: []string{encrypted}},
			Options{Prompter: prompter, HostKeyMode: HostKeyNone}); err == nil {
			t.Fatal("Dial should have failed: the server accepts a different key")
		}
		for _, question := range prompter.asked {
			if strings.Contains(question, "passphrase") {
				t.Errorf("the passphrase was asked for a key the server refused: %q", question)
			}
		}
	})

	t.Run("accepted key is unlocked and used", func(t *testing.T) {
		server := startServer(t, serverOptions{authorized: encryptedPublic})
		prompter := &stubPrompter{secret: "hunter2"}
		if _, err := dialServer(t, server,
			Overrides{IdentityFiles: []string{encrypted}},
			Options{Prompter: prompter, HostKeyMode: HostKeyNone}); err != nil {
			t.Fatalf("Dial: %v", err)
		}
		if len(prompter.asked) == 0 {
			t.Error("the passphrase was never asked for")
		}
	})
}

// An encrypted key with nobody to ask is a clear error, not a hang.
func TestEncryptedKeyWithoutAPrompter(t *testing.T) {
	isolatedHome(t)
	encrypted, _ := writeEncryptedKeyPair(t, t.TempDir(), "id_encrypted", "hunter2")

	_, err := loadIdentity(encrypted, nil)
	if err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("err = %v, want an encrypted-key error", err)
	}
}

// A missing agent must not be fatal on its own: the identity files are still
// worth trying, and the eventual error should say what was actually wrong.
func TestPublicKeySignersReportsWhyThereAreNoKeys(t *testing.T) {
	isolatedHome(t)
	auth := newAuthenticator(&Destination{}, Options{AuthSock: filepath.Join(t.TempDir(), "absent")})
	defer auth.Close()

	_, err := auth.publicKeySigners()
	if err == nil {
		t.Fatal("no agent and no identity files should be an error")
	}
	if !strings.Contains(err.Error(), "agent") {
		t.Errorf("error = %q, want it to mention the agent", err)
	}
}

func TestResolveAgentPath(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/from/environment")

	tests := []struct {
		name       string
		explicit   string
		fromConfig string
		want       string
	}{
		{name: "environment by default", want: "/from/environment"},
		{name: "ssh_config beats the environment", fromConfig: "/from/config", want: "/from/config"},
		{name: "explicit beats ssh_config", explicit: "/from/flag", fromConfig: "/from/config", want: "/from/flag"},
		{name: "quotes are stripped", fromConfig: `"/quoted/path"`, want: "/quoted/path"},
		{name: "the literal SSH_AUTH_SOCK means the environment", fromConfig: "SSH_AUTH_SOCK", want: "/from/environment"},
		{name: "none disables the agent", fromConfig: "none", want: ""},
		{name: "none is case-insensitive", fromConfig: "None", want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := resolveAgentPath(test.explicit, test.fromConfig); got != test.want {
				t.Errorf("resolveAgentPath(%q, %q) = %q, want %q", test.explicit, test.fromConfig, got, test.want)
			}
		})
	}
}

func TestAuthHint(t *testing.T) {
	d := &Destination{Alias: "devbox", Host: "10.0.0.7"}

	got := authHint(errText("ssh: unable to authenticate, attempted methods [none publickey]"), d,
		[]string{"agent (2 keys)", "/home/jeff/.ssh/id_ed25519"})
	if !strings.Contains(got, "agent (2 keys)") || !strings.Contains(got, "id_ed25519") {
		t.Errorf("the hint should list what was offered:\n%s", got)
	}
	if !strings.Contains(got, "Agent keys are offered first") {
		t.Errorf("the hint should explain the ordering:\n%s", got)
	}
	if !strings.Contains(got, "ssh-add -l") {
		t.Errorf("the hint should suggest checking the agent:\n%s", got)
	}
	if !strings.Contains(got, "devbox") {
		t.Errorf("the hint should name the host the user knows:\n%s", got)
	}

	d.IdentitiesOnly = true
	if got := authHint(errText("ssh: unable to authenticate"), d, nil); !strings.Contains(got, "IdentitiesOnly") {
		t.Errorf("the hint should mention IdentitiesOnly:\n%s", got)
	}

	// Unrelated failures are left alone.
	if got := authHint(errText("connection reset"), d, nil); got != "" {
		t.Errorf("hint = %q, want none for an unrelated error", got)
	}
}

type errText string

func (e errText) Error() string { return string(e) }

// writeEncryptedKeyPair writes a passphrase-protected private key and its .pub
// beside it.
func writeEncryptedKeyPair(t *testing.T, dir, name, passphrase string) (string, ssh.PublicKey) {
	t.Helper()
	key := generateKey(t, "ed25519")
	block, err := ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte(passphrase))
	if err != nil {
		t.Fatalf("marshalling encrypted key: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	public := signerFor(t, key).PublicKey()
	if err := os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(public), 0o644); err != nil {
		t.Fatalf("writing public key: %v", err)
	}
	return path, public
}
