package sshx

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// verifierIn builds a verifier over the known_hosts of the isolated HOME the
// test has already set up.
func verifierIn(t *testing.T, mode HostKeyMode, prompter Prompter) *HostKeyVerifier {
	t.Helper()
	files, err := DefaultKnownHostsFiles()
	if err != nil {
		t.Fatalf("DefaultKnownHostsFiles: %v", err)
	}
	verifier, err := HostKeyPolicy{Mode: mode, Files: files, Prompter: prompter}.Verifier()
	if err != nil {
		t.Fatalf("building verifier: %v", err)
	}
	return verifier
}

// verifierOver builds a verifier over one specific known_hosts file.
func verifierOver(t *testing.T, path string) *HostKeyVerifier {
	t.Helper()
	verifier, err := HostKeyPolicy{Mode: HostKeyAsk, Files: []string{path}}.Verifier()
	if err != nil {
		t.Fatalf("building verifier: %v", err)
	}
	return verifier
}

// record trusts key for devbox the way a first connection would, so the rest
// of the test can ask what known_hosts now holds.
func record(t *testing.T, key ssh.PublicKey) {
	t.Helper()
	if err := verifierIn(t, HostKeyAcceptNew, &stubPrompter{}).Check("devbox:22", remoteAddr(t), key); err != nil {
		t.Fatalf("recording a host key: %v", err)
	}
}

func remoteAddr(t *testing.T) net.Addr {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", "10.0.0.7:22")
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestHostKeyNoneSkipsVerification(t *testing.T) {
	isolatedHome(t)
	if err := verifierIn(t, HostKeyNone, nil).Check("devbox:22", remoteAddr(t), newPublicKey(t, "ed25519")); err != nil {
		t.Errorf("insecure callback rejected a key: %v", err)
	}
}

func TestHostKeyAskAcceptsAndRecords(t *testing.T) {
	home := isolatedHome(t)
	prompter := &stubPrompter{confirm: true}

	key := newPublicKey(t, "ed25519")
	if err := verifierIn(t, HostKeyAsk, prompter).Check("devbox:22", remoteAddr(t), key); err != nil {
		t.Fatalf("callback rejected an accepted key: %v", err)
	}
	if len(prompter.asked) == 0 {
		t.Error("the user was never asked")
	}
	// The fingerprint is the only thing that makes the answer meaningful.
	if len(prompter.notices) == 0 || !strings.Contains(prompter.notices[0], ssh.FingerprintSHA256(key)) {
		t.Errorf("the fingerprint was not shown: %v", prompter.notices)
	}

	// The key must be written to known_hosts, so the next connection is silent.
	data, err := os.ReadFile(filepath.Join(home, ".ssh", "known_hosts"))
	if err != nil {
		t.Fatalf("reading known_hosts: %v", err)
	}
	if !strings.Contains(string(data), string(ssh.MarshalAuthorizedKey(key))[:40]) {
		t.Errorf("known_hosts does not contain the accepted key:\n%s", data)
	}

	refuse := &stubPrompter{confirm: false}
	if err := verifierIn(t, HostKeyAsk, refuse).Check("devbox:22", remoteAddr(t), key); err != nil {
		t.Errorf("a recorded key should verify without asking again: %v", err)
	}
}

func TestHostKeyAskRejection(t *testing.T) {
	isolatedHome(t)
	err := verifierIn(t, HostKeyAsk, &stubPrompter{confirm: false}).
		Check("devbox:22", remoteAddr(t), newPublicKey(t, "ed25519"))
	if !errors.Is(err, ErrHostKeyRejected) {
		t.Errorf("err = %v, want ErrHostKeyRejected", err)
	}
}

func TestHostKeyAskWithoutAPrompter(t *testing.T) {
	isolatedHome(t)
	err := verifierIn(t, HostKeyAsk, nil).Check("devbox:22", remoteAddr(t), newPublicKey(t, "ed25519"))
	if !errors.Is(err, ErrNoTerminal) {
		t.Errorf("err = %v, want ErrNoTerminal", err)
	}
	if !strings.Contains(err.Error(), "ssh-keyscan") {
		t.Errorf("err = %v, want it to say how to record the host ahead of time", err)
	}
}

func TestHostKeyStrictRefusesUnknownHosts(t *testing.T) {
	isolatedHome(t)
	err := verifierIn(t, HostKeyStrict, &stubPrompter{confirm: true}).
		Check("devbox:22", remoteAddr(t), newPublicKey(t, "ed25519"))
	if err == nil || !strings.Contains(err.Error(), "not in known_hosts") {
		t.Errorf("err = %v, want a strict-mode rejection", err)
	}
}

func TestHostKeyAcceptNewDoesNotAsk(t *testing.T) {
	home := isolatedHome(t)
	prompter := &stubPrompter{}

	if err := verifierIn(t, HostKeyAcceptNew, prompter).Check("devbox:22", remoteAddr(t), newPublicKey(t, "ed25519")); err != nil {
		t.Fatalf("accept-new rejected an unknown host: %v", err)
	}
	if len(prompter.asked) != 0 {
		t.Errorf("accept-new should not prompt, but asked %v", prompter.asked)
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "known_hosts")); err != nil {
		t.Errorf("known_hosts was not written: %v", err)
	}
}

// A key that changed is never auto-accepted, in any mode short of "no".
func TestHostKeyChangedIsAlwaysRefused(t *testing.T) {
	isolatedHome(t)
	record(t, newPublicKey(t, "ed25519"))

	for _, mode := range []HostKeyMode{HostKeyAcceptNew, HostKeyAsk, HostKeyStrict} {
		err := verifierIn(t, mode, &stubPrompter{confirm: true}).
			Check("devbox:22", remoteAddr(t), newPublicKey(t, "ed25519")) // a different key
		if err == nil {
			t.Errorf("mode %q accepted a changed host key", mode)
			continue
		}
		if !strings.Contains(err.Error(), "IDENTIFICATION HAS CHANGED") {
			t.Errorf("mode %q error = %v, want the changed-key warning", mode, err)
		}
		if !strings.Contains(err.Error(), "ssh-keygen -R") {
			t.Errorf("mode %q error should tell the user how to fix it: %v", mode, err)
		}
	}
}

// A key type we have not recorded for a known host is a new key, not a changed
// one — ssh(1) only compares within one algorithm, and so do we.
func TestHostKeyOfANewTypeIsNotAChangedKey(t *testing.T) {
	isolatedHome(t)
	record(t, newPublicKey(t, "ed25519"))

	prompter := &stubPrompter{confirm: true}
	if err := verifierIn(t, HostKeyAsk, prompter).Check("devbox:22", remoteAddr(t), newPublicKey(t, "ecdsa")); err != nil {
		t.Fatalf("an unrecorded key type should be offered for approval: %v", err)
	}
	if len(prompter.notices) == 0 || !strings.Contains(prompter.notices[0], "different key type") {
		t.Errorf("the user should be told the host is known by another key type: %v", prompter.notices)
	}
}

func TestKnownHostsFileIsCreated(t *testing.T) {
	home := isolatedHome(t)
	if _, err := DefaultKnownHostsFiles(); err != nil {
		t.Fatalf("DefaultKnownHostsFiles: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "known_hosts")); err != nil {
		t.Errorf("known_hosts should have been created: %v", err)
	}
}

// ---- Algorithm preference ----

// The regression this exists for: a host with both an Ed25519 and an ECDSA
// key, recorded as Ed25519, must not be asked for its ECDSA key.
func TestAlgorithmsForPrefersRecordedTypes(t *testing.T) {
	address := "127.0.0.1:2222"
	verifier := verifierOver(t, writeKnownHosts(t, address, newPublicKey(t, "ed25519")))

	algorithms := verifier.AlgorithmsFor(address)
	if len(algorithms) == 0 || algorithms[0] != ssh.KeyAlgoED25519 {
		t.Fatalf("algorithms = %v, want the recorded ssh-ed25519 first", algorithms)
	}
	// The others stay on the list, so a genuine key rotation still negotiates
	// and is reported honestly instead of failing to agree on an algorithm.
	if !slices.Contains(algorithms, ssh.KeyAlgoECDSA256) {
		t.Errorf("algorithms = %v, want the remaining types kept as fallbacks", algorithms)
	}
}

func TestAlgorithmsForOrdersEveryRecordedTypeFirst(t *testing.T) {
	address := "127.0.0.1:2222"
	verifier := verifierOver(t, writeKnownHosts(t, address,
		newPublicKey(t, "ed25519"), newPublicKey(t, "ecdsa")))

	algorithms := verifier.AlgorithmsFor(address)
	if len(algorithms) < 2 {
		t.Fatalf("algorithms = %v", algorithms)
	}
	recorded := []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256}
	if !reflect.DeepEqual(algorithms[:2], recorded) {
		t.Errorf("algorithms = %v, want the two recorded types first", algorithms)
	}
}

// A known_hosts line says "ssh-rsa", but a current server signs with
// rsa-sha2-*. Listing only the key type would pin the connection to the
// deprecated SHA-1 algorithm that many servers no longer offer.
func TestAlgorithmsForExpandsRSAToSHA2(t *testing.T) {
	address := "127.0.0.1:2222"
	verifier := verifierOver(t, writeKnownHosts(t, address, newPublicKey(t, "rsa")))

	algorithms := verifier.AlgorithmsFor(address)
	want := []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	if len(algorithms) < len(want) || !reflect.DeepEqual(algorithms[:len(want)], want) {
		t.Errorf("algorithms = %v, want %v first", algorithms, want)
	}
}

func TestAlgorithmsForUnknownHostIsUnrestricted(t *testing.T) {
	verifier := verifierOver(t, writeKnownHosts(t, "127.0.0.1:2222", newPublicKey(t, "ed25519")))
	if got := verifier.AlgorithmsFor("elsewhere:22"); got != nil {
		t.Errorf("AlgorithmsFor(unknown host) = %v, want nil so nothing is restricted", got)
	}
}

func TestAlgorithmsForIsUnsetWhenVerificationIsOff(t *testing.T) {
	isolatedHome(t)
	record(t, newPublicKey(t, "ed25519"))
	if got := verifierIn(t, HostKeyNone, nil).AlgorithmsFor("devbox:22"); got != nil {
		t.Errorf("verification is off, so there is nothing to prefer, got %v", got)
	}
}

// ---- End to end ----

// A real sshd holds several host keys; known_hosts usually records just one of
// them. x/crypto/ssh's default preference puts ECDSA ahead of Ed25519 — the
// opposite of OpenSSH — so without reordering, a host recorded by its Ed25519
// key gets its ECDSA key presented instead, and the check reports a changed
// host key on a host that has not changed at all.
func TestDialPrefersHostKeyTypesRecordedInKnownHosts(t *testing.T) {
	isolatedHome(t)
	clientKey := generateKey(t, "ed25519")

	server := startServer(t, serverOptions{
		authorized:  signerFor(t, clientKey).PublicKey(),
		hostSigners: []ssh.Signer{newHostSigner(t, "ecdsa"), newHostSigner(t, "ed25519")},
	})

	// Only the Ed25519 key is recorded, exactly as it would be for a host first
	// reached with a client that preferred Ed25519.
	knownHosts := writeKnownHosts(t, server.addr(), server.hostKeys[1])

	if _, err := dialServer(t, server, Overrides{}, Options{
		AuthSock:        startTestAgent(t, clientKey).path,
		KnownHostsFiles: []string{knownHosts},
	}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
}

// The corresponding safety check: preferring recorded key types must not turn a
// genuinely different key of a recorded type into a pass.
func TestDialStillRefusesAGenuinelyChangedKey(t *testing.T) {
	isolatedHome(t)
	clientKey := generateKey(t, "ed25519")

	server := startServer(t, serverOptions{authorized: signerFor(t, clientKey).PublicKey()})
	impostor := newPublicKey(t, "ed25519")

	// known_hosts records a different Ed25519 key for this address.
	knownHosts := writeKnownHosts(t, server.addr(), impostor)

	_, err := dialServer(t, server, Overrides{}, Options{
		AuthSock:        startTestAgent(t, clientKey).path,
		KnownHostsFiles: []string{knownHosts},
	})
	if err == nil {
		t.Fatal("a changed host key must not be accepted")
	}
	if !strings.Contains(err.Error(), "IDENTIFICATION HAS CHANGED") {
		t.Fatalf("err = %v, want a host key change refusal", err)
	}
	// The message has to name both keys, or there is no way to tell a rebuilt
	// host from an attack.
	for _, want := range []string{
		ssh.FingerprintSHA256(server.hostKey()),
		ssh.FingerprintSHA256(impostor),
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to mention %s", err, want)
		}
	}
}
