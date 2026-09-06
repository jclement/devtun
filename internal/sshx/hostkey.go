// Host key verification.
//
// This is the part of speaking SSH ourselves that is easiest to get wrong and
// worst to get wrong: devtun forwards ports and secrets, so accepting a key we
// have not seen before without saying so would defeat the point. The rules
// match OpenSSH's, and StrictHostKeyChecking selects between them: an unknown
// host is a question, a *changed* key is a hard failure that nothing short of
// turning verification off can wave through.
//
// The subtle part is algorithm selection. A server usually has several host
// keys — RSA, ECDSA and Ed25519 — and known_hosts typically records only the
// one that was current when you first connected. OpenSSH therefore reorders its
// HostKeyAlgorithms to prefer the types it already knows for that host.
// x/crypto/ssh does not, and its default order differs from OpenSSH's, so the
// server can quite legitimately present a key of a type your known_hosts has
// never seen — which is indistinguishable, to a naive check, from the key
// having changed. AlgorithmsFor exists to close exactly that gap.
package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyMode controls what happens when a host key is unknown. It mirrors
// ssh(1)'s StrictHostKeyChecking.
type HostKeyMode string

const (
	// HostKeyAsk prompts before trusting an unknown host.
	HostKeyAsk HostKeyMode = "ask"
	// HostKeyAcceptNew trusts and records unknown hosts without asking, but
	// still refuses a host whose key has changed.
	HostKeyAcceptNew HostKeyMode = "accept-new"
	// HostKeyStrict refuses anything not already in known_hosts.
	HostKeyStrict HostKeyMode = "yes"
	// HostKeyNone disables verification entirely.
	HostKeyNone HostKeyMode = "no"
)

// ParseHostKeyMode maps an ssh_config StrictHostKeyChecking value.
func ParseHostKeyMode(s string) HostKeyMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "yes", "true":
		return HostKeyStrict
	case "no", "false", "off":
		return HostKeyNone
	case "accept-new":
		return HostKeyAcceptNew
	default:
		return HostKeyAsk
	}
}

// ErrHostKeyRejected is returned when the user declines an unknown host key.
var ErrHostKeyRejected = errors.New("host key rejected")

// HostKeyPolicy decides what to do about host keys.
type HostKeyPolicy struct {
	// Mode is what to do about a host that is not recorded yet.
	Mode HostKeyMode
	// Files are known_hosts files, in order. The first is written to when a new
	// host is accepted.
	Files []string
	// Prompter asks about an unknown host. Nil means nobody can be asked, so
	// HostKeyAsk becomes a refusal rather than a hang.
	Prompter Prompter
}

// HostKeyVerifier carries the callback the handshake uses, plus the algorithm
// preference derived from what known_hosts actually records for a host.
type HostKeyVerifier struct {
	// Check is the ssh.HostKeyCallback implementing the policy.
	Check ssh.HostKeyCallback

	lookup ssh.HostKeyCallback
}

// DefaultKnownHostsFiles returns the usual locations, creating the user's file
// if it is missing so that first use has somewhere to record an answer.
func DefaultKnownHostsFiles() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("locating home directory: %w", err)
	}
	primary := filepath.Join(home, ".ssh", "known_hosts")
	if _, err := os.Stat(primary); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(primary), 0o700); err != nil {
			return nil, fmt.Errorf("creating .ssh directory: %w", err)
		}
		if err := os.WriteFile(primary, nil, 0o600); err != nil {
			return nil, fmt.Errorf("creating %s: %w", primary, err)
		}
	}
	files := []string{primary}
	if secondary := filepath.Join(home, ".ssh", "known_hosts2"); fileExists(secondary) {
		files = append(files, secondary)
	}
	return files, nil
}

// Verifier builds the host key machinery implementing this policy.
func (p HostKeyPolicy) Verifier() (*HostKeyVerifier, error) {
	if p.Mode == HostKeyNone {
		return &HostKeyVerifier{Check: ssh.InsecureIgnoreHostKey()}, nil //nolint:gosec // explicitly requested
	}
	if len(p.Files) == 0 {
		return nil, errors.New("no known_hosts files configured")
	}
	lookup, err := knownhosts.New(p.Files...)
	if err != nil {
		return nil, fmt.Errorf("reading known_hosts: %w", err)
	}

	verifier := &HostKeyVerifier{lookup: lookup}
	verifier.Check = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := lookup(hostname, remote, key)
		if err == nil {
			return nil
		}

		var keyError *knownhosts.KeyError
		if !errors.As(err, &keyError) {
			return err
		}

		// Only a recorded key of the *same* algorithm can contradict this one.
		// Records of other algorithms mean the host has a key type we have not
		// seen before, which is a new key, not a changed one.
		if changed := keysOfType(keyError.Want, key); len(changed) > 0 {
			return changedKeyError(hostname, key, changed)
		}

		switch p.Mode {
		case HostKeyStrict:
			return fmt.Errorf("host %s is not in known_hosts (%s) and StrictHostKeyChecking is yes",
				hostname, ssh.FingerprintSHA256(key))
		case HostKeyAcceptNew:
			notify(p.Prompter, fmt.Sprintf("Permanently added '%s' (%s) to known hosts.", hostname, key.Type()))
		default:
			if p.Prompter == nil {
				return fmt.Errorf(
					"host %s is not in known_hosts (%s) and there is no terminal to confirm on.\n"+
						"Connect once interactively, or add it with `ssh-keyscan`, before running unattended: %w",
					hostname, ssh.FingerprintSHA256(key), ErrNoTerminal)
			}
			notice := fmt.Sprintf(
				"The authenticity of host '%s' can't be established.\n%s key fingerprint is %s.\n"+
					"Check this fingerprint against the server before accepting.",
				hostname, key.Type(), ssh.FingerprintSHA256(key))
			if len(keyError.Want) > 0 {
				notice += fmt.Sprintf("\nThis host is already known by a different key type (%s).", keyError.Want[0].Key.Type())
			}
			p.Prompter.Notice(notice)
			accepted, err := p.Prompter.Confirm("Are you sure you want to continue connecting?")
			if err != nil {
				return err
			}
			if !accepted {
				return ErrHostKeyRejected
			}
		}
		return appendKnownHost(p.Files[0], hostname, remote, key)
	}
	return verifier, nil
}

// AlgorithmsFor returns the host key algorithms to advertise when connecting to
// address ("host:port"): the ones known_hosts already records first, then
// everything else. Nil means no opinion.
//
// Without the reordering the client offers its own global preference — ECDSA
// ahead of Ed25519 — and a server holding both hands back the ECDSA key even
// though known_hosts records the Ed25519 one. The host is then reported as
// unknown, or worse as changed, on a host that has not changed at all. The
// remaining algorithms stay on the list behind the recorded ones, so a host
// that genuinely rotated to a new key type still negotiates and gets the honest
// "this key is new" conversation instead of failing to agree on an algorithm.
//
// There is no API in x/crypto/ssh/knownhosts to enumerate a host's keys, but
// its mismatch error carries exactly that list. Offering it a key nobody could
// have recorded — freshly generated random bytes — therefore reports back what
// *is* recorded, using the library's own host matching, so hashed entries,
// wildcards and per-port entries all behave identically to a real lookup.
func (v *HostKeyVerifier) AlgorithmsFor(address string) []string {
	if v.lookup == nil {
		return nil
	}
	probe, err := unmatchableKey()
	if err != nil {
		return nil
	}

	var keyError *knownhosts.KeyError
	if !errors.As(v.lookup(address, literalAddr(address), probe), &keyError) {
		return nil
	}

	var algorithms []string
	add := func(candidates []string) {
		for _, algorithm := range candidates {
			if !slices.Contains(algorithms, algorithm) {
				algorithms = append(algorithms, algorithm)
			}
		}
	}
	for _, known := range keyError.Want {
		add(signatureAlgorithms(known.Key.Type()))
	}
	if len(algorithms) == 0 {
		return nil // Nothing recorded: no opinion, leave the default order.
	}
	add(ssh.SupportedAlgorithms().HostKeys)
	add(ssh.InsecureAlgorithms().HostKeys)
	return algorithms
}

// signatureAlgorithms expands a host key type into the signature algorithms
// that key can produce. It matters for RSA: a known_hosts line says `ssh-rsa`,
// but a current server signs with rsa-sha2-512 or rsa-sha2-256, and listing
// only `ssh-rsa` would force the deprecated SHA-1 algorithm that many servers
// no longer offer.
func signatureAlgorithms(keyType string) []string {
	switch keyType {
	case ssh.KeyAlgoRSA:
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	case ssh.CertAlgoRSAv01:
		return []string{ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSAv01}
	default:
		return []string{keyType}
	}
}

// unmatchableKey builds a public key from random bytes. It is never anybody's
// host key, so a lookup against it always reports a mismatch — which is what
// makes the recorded keys visible.
func unmatchableKey() (ssh.PublicKey, error) {
	material := make([]byte, ed25519.PublicKeySize)
	if _, err := rand.Read(material); err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(ed25519.PublicKey(material))
}

// literalAddr satisfies the net.Addr the knownhosts callback dereferences. The
// hostname argument takes precedence in its lookup, so this only has to parse.
type literalAddr string

func (a literalAddr) Network() string { return "tcp" }
func (a literalAddr) String() string  { return string(a) }

// keysOfType picks out the recorded keys using the same algorithm as key. Only
// those can say anything about whether the host's identity changed; a recorded
// key of a different type is simply a different key.
func keysOfType(known []knownhosts.KnownKey, key ssh.PublicKey) []knownhosts.KnownKey {
	var same []knownhosts.KnownKey
	for _, k := range known {
		if k.Key.Type() == key.Type() {
			same = append(same, k)
		}
	}
	return same
}

// changedKeyError reports a genuine mismatch. It names both keys and where the
// recorded one came from, because "which line do I remove, and was it really
// this host" is the only question the user has at that point.
func changedKeyError(hostname string, presented ssh.PublicKey, want []knownhosts.KnownKey) error {
	var recorded strings.Builder
	for _, known := range want {
		fmt.Fprintf(&recorded, "\n  recorded   %-22s %s  (%s:%d)",
			known.Key.Type(), ssh.FingerprintSHA256(known.Key), known.Filename, known.Line)
	}
	return fmt.Errorf(
		"REMOTE HOST IDENTIFICATION HAS CHANGED for %s.\n  presented  %-22s %s%s\n"+
			"This may be a machine-in-the-middle attack, or the host may have been rebuilt.\n"+
			"If you genuinely rebuilt it, remove the old line with `ssh-keygen -R %s`. Otherwise, do not connect",
		hostname, presented.Type(), ssh.FingerprintSHA256(presented), recorded.String(), hostOnly(hostname))
}

// appendKnownHost records the accepted key so the question is asked only once.
func appendKnownHost(path, hostname string, remote net.Addr, key ssh.PublicKey) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening %s to record the host key: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	addresses := []string{knownhosts.Normalize(hostname)}
	if remote != nil {
		if n := knownhosts.Normalize(remote.String()); n != addresses[0] {
			addresses = append(addresses, n)
		}
	}
	if _, err := file.WriteString(knownhosts.Line(addresses, key) + "\n"); err != nil {
		return fmt.Errorf("writing host key to %s: %w", path, err)
	}
	return nil
}

// hostOnly strips the :port that ssh.HostKeyCallback receives, which is not
// what ssh-keygen -R expects.
func hostOnly(hostname string) string {
	if host, _, err := net.SplitHostPort(hostname); err == nil {
		return host
	}
	return strings.Trim(hostname, "[]")
}
