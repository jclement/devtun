package sshagent

import (
	"bytes"
	"github.com/jclement/devtun/internal/prompt"

	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// sessionBindExtension is how OpenSSH 8.9 and later tell an agent where a
// signature is about to be used. It is sent once per agent connection, before
// any signing, and it is the only reason this service can say "github.com"
// rather than "something on that box wants to sign".
const sessionBindExtension = "session-bind@openssh.com"

// unknownDestination is what a subject says when no session-bind arrived.
//
// Saying so plainly matters more than it looks. An older `ssh` sends no bind at
// all, and a subject that quietly omitted the destination would read like a
// signature scoped to somewhere, matched by rules written for somewhere, and
// approved on the strength of a precision it never had.
const unknownDestination = "(destination unknown)"

// destination is where a connection's signatures are going, as far as we can
// know it.
type destination struct {
	// hostKey is the destination's host key, proven by the session-bind
	// signature. Nil when no usable bind arrived.
	hostKey ssh.PublicKey
	// name is what known_hosts calls that key, empty when it is not there.
	name string
	// forwarding reports that `ssh` will forward the agent onward from this
	// destination, which means the box being signed into can reach these keys
	// too. It is reported rather than folded into the subject: it changes how
	// alarming a request is, not which request it is.
	forwarding bool
}

// String renders the destination for a subject and a prompt, preferring the
// name a human recognises and never claiming more than is known.
func (d destination) String() string {
	switch {
	case d.name != "":
		return d.name
	case d.hostKey != nil:
		return ssh.FingerprintSHA256(d.hostKey)
	default:
		return unknownDestination
	}
}

// rows are the destination facts worth putting in front of a human deciding.
//
// Onward forwarding earns a line of its own. It does not change *which* request
// this is — the subject is the same either way — but it changes how alarming
// the request is: the box being signed into can reach these keys too, so
// approving is lending them one hop further than it looks.
func (d destination) rows() []prompt.Row {
	var rows []prompt.Row
	switch {
	case d.name != "" && d.hostKey != nil:
		rows = append(rows, prompt.Row{Label: "host key", Value: ssh.FingerprintSHA256(d.hostKey)})
	case d.hostKey == nil:
		rows = append(rows, prompt.Row{
			Label: "warning",
			Value: "this ssh did not say where it is signing in to (needs OpenSSH 8.9+)",
		})
	}
	if d.forwarding {
		rows = append(rows, prompt.Row{
			Label: "onward",
			Value: "that host can use these keys too — agent forwarding is on beyond it",
		})
	}
	return rows
}

// subjectFor names one signing request for the policy store and the prompt.
//
// The format is `<key type> <key fingerprint> → <destination>`. Both halves
// have to be there: the key alone would let a grant for a throwaway host cover
// a signature into production, and the destination alone would let a grant for
// one of your keys cover all of them.
//
// It is matched against globs in the user's config, so it is a stable string
// and not a rendering: `* → github.com` allows any key into GitHub, and
// `ssh-ed25519 SHA256:… → **` allows one key anywhere.
func subjectFor(key ssh.PublicKey, dest destination) string {
	return fmt.Sprintf("%s %s → %s", key.Type(), ssh.FingerprintSHA256(key), dest)
}

// sessionBind is the payload of a session-bind@openssh.com request: the
// destination's host key, the session identifier, that host key's signature
// over the identifier, and whether the agent is being forwarded onward.
type sessionBind struct {
	HostKey      []byte
	SessionID    []byte
	Signature    []byte
	IsForwarding bool
}

// parseSessionBind reads and *verifies* a bind payload.
//
// The verification is the part that matters. Without it the destination is
// merely something the client said, and a hostile process on the dev box could
// claim GitHub's host key, collect the grant a human gave for GitHub, and spend
// it authenticating somewhere else entirely — turning the most useful thing
// this service does into the most misleading. The signature is over the session
// identifier and can only have been made by whoever holds that host key, so
// checking it is what makes the destination a fact rather than a claim. It is
// what OpenSSH's own agent does with this message, for the same reason.
func parseSessionBind(contents []byte) (sessionBind, ssh.PublicKey, error) {
	var bind sessionBind
	if err := ssh.Unmarshal(contents, &bind); err != nil {
		return sessionBind{}, nil, fmt.Errorf("unreadable session-bind payload: %w", err)
	}

	hostKey, err := ssh.ParsePublicKey(bind.HostKey)
	if err != nil {
		return sessionBind{}, nil, fmt.Errorf("unreadable session-bind host key: %w", err)
	}

	var signature ssh.Signature
	if err := ssh.Unmarshal(bind.Signature, &signature); err != nil {
		return sessionBind{}, nil, fmt.Errorf("unreadable session-bind signature: %w", err)
	}
	if err := hostKey.Verify(bind.SessionID, &signature); err != nil {
		return sessionBind{}, nil, fmt.Errorf("session-bind signature does not match the host key it names: %w", err)
	}
	return bind, hostKey, nil
}

// destinationFor turns a verified bind into the destination a human will read.
func (s *Service) destinationFor(bind sessionBind, hostKey ssh.PublicKey) destination {
	return destination{
		hostKey:    hostKey,
		name:       s.names.nameOf(hostKey),
		forwarding: bind.IsForwarding,
	}
}

// hostNames answers "what do I call the box holding this host key", from the
// user's own known_hosts files.
//
// This is naming, not authentication — the bind signature already established
// which key is at the far end. But the name ends up in the subject, so it has
// to be trustworthy anyway, and it is: known_hosts is the user's own record of
// which key belongs to which name, and it is exactly what `ssh` itself trusts
// to answer the same question.
type hostNames struct {
	paths []string
	once  sync.Once
	byKey map[string]string
}

func newHostNames(paths []string) *hostNames { return &hostNames{paths: paths} }

// nameOf returns the known_hosts name for a host key, or empty when there is
// none — in which case the caller falls back to the fingerprint.
func (h *hostNames) nameOf(key ssh.PublicKey) string {
	if key == nil {
		return ""
	}
	h.once.Do(h.load)
	return h.byKey[string(key.Marshal())]
}

// load reads every known_hosts file once. A file that is missing or unreadable
// costs nothing but a less readable prompt, so nothing is reported: the
// fingerprint fallback is always correct.
func (h *hostNames) load() {
	h.byKey = make(map[string]string)
	for _, path := range h.paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		h.absorb(data)
	}
}

// absorb indexes one file's entries by key blob.
//
// Lines are parsed one at a time rather than by walking the parser's `rest`,
// because that parser abandons the remainder of the input on the first entry it
// cannot read. One `@revoked` line or one key type from a newer OpenSSH would
// otherwise silently cost every host below it its name.
func (h *hostNames) absorb(data []byte) {
	for _, line := range bytes.Split(data, []byte("\n")) {
		marker, hosts, key, _, _, err := ssh.ParseKnownHosts(line)
		if err != nil {
			continue
		}
		// A marker line names a certificate authority or a revoked key, not the
		// host key a bind will present.
		if marker != "" {
			continue
		}
		name := readableHost(hosts)
		if name == "" {
			continue
		}
		// First entry wins, so a key listed under two names resolves the same
		// way on every run.
		if _, seen := h.byKey[string(key.Marshal())]; !seen {
			h.byKey[string(key.Marshal())] = name
		}
	}
}

// readableHost picks the first pattern from an entry that is actually a name a
// human would recognise. Hashed entries (HashKnownHosts, which is the default
// on some distributions) cannot be reversed at all, and a wildcard or negation
// is a pattern rather than a host, so any of those leaves the destination named
// by fingerprint instead.
func readableHost(hosts []string) string {
	for _, host := range hosts {
		switch {
		case host == "":
		case strings.HasPrefix(host, "|"), strings.HasPrefix(host, "!"):
		case strings.ContainsAny(host, "*?"):
		default:
			return host
		}
	}
	return ""
}
