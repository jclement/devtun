package sshagent

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/jclement/devtun/internal/prompt"
)

// The agent protocol hands over a key and some bytes, and nothing about what
// the bytes are for. A grant that says "this key, for github.com" is only worth
// something if the bytes it lets through really are a login to github.com, so
// this file reads them and decides what a signature would actually be good for
// before any policy sees it. It is the check OpenSSH's own agent makes for a
// destination-restricted key, and for the same reason: without it a remote box
// holding one genuine session-bind for an approved destination could have any
// payload signed under that approval — including a login to somewhere else.

// Message and method names from RFC 4252 and OpenSSH's PROTOCOL file.
const (
	msgUserAuthRequest = 50
	userAuthService    = "ssh-connection"
	methodPublicKey    = "publickey"
	methodHostBound    = "publickey-hostbound-v00@openssh.com"
)

// sshsigMagic opens every SSHSIG signed blob (OpenSSH's PROTOCOL.sshsig). It is
// what `ssh-keygen -Y sign` signs, and so what git signs when gpg.format is ssh.
const sshsigMagic = "SSHSIG"

// arbitraryData is the destination half of a subject for bytes that are neither
// an SSH login nor an SSHSIG blob. It is parenthesised, like unknownDestination,
// so it can never be mistaken for, or matched as, a host name.
const arbitraryData = "(arbitrary data)"

// targetKind says which of the three things a signature can be.
type targetKind int

const (
	// targetLogin is SSH public-key user authentication: the only kind a
	// destination grant covers.
	targetLogin targetKind = iota
	// targetSSHSIG is a namespaced SSHSIG signature — a git commit or tag, an
	// `ssh-keygen -Y sign` of a file.
	targetSSHSIG
	// targetArbitrary is anything else. devtun cannot say what it will be used
	// for, so it is its own subject and is asked about on its own.
	targetArbitrary
)

// target is what one signature will be good for, as far as the bytes say.
type target struct {
	kind targetKind
	// dest is the login's destination. For a login it is the connection's
	// binding, or the zero destination when the binding cannot vouch for this
	// particular login; for the other kinds it is unused.
	dest destination
	// via is the binding a login was not covered by, when the connection was
	// bound to a host that forwards the agent onward: the login is then going
	// somewhere beyond that host, which is worth telling the human.
	via destination
	// namespace is the SSHSIG namespace, already made safe to put in a subject.
	namespace string
}

// String is the destination half of a subject. It is a stable string matched
// by rules, not a rendering: `* → github.com` allows any key to log in to
// GitHub, `* → sshsig:git` allows any key to sign git objects.
func (t target) String() string {
	switch t.kind {
	case targetSSHSIG:
		return "sshsig:" + t.namespace
	case targetArbitrary:
		return arbitraryData
	default:
		return t.dest.String()
	}
}

// rows are the facts about the target worth putting in front of a human.
func (t target) rows() []prompt.Row {
	switch t.kind {
	case targetSSHSIG:
		what := fmt.Sprintf("an SSHSIG signature in the %q namespace", t.namespace)
		if t.namespace == "git" {
			what = "a git commit or tag signature (SSHSIG, namespace \"git\")"
		}
		return []prompt.Row{{Label: "signing", Value: what}}
	case targetArbitrary:
		return []prompt.Row{{
			Label: "warning",
			Value: "this is not an SSH login or an SSHSIG signature — devtun cannot tell what it will be used for",
		}}
	}
	rows := t.dest.rows()
	if t.via.hostKey != nil {
		rows = append(rows, prompt.Row{
			Label: "via",
			Value: t.via.String() + ", which has your agent forwarded to it",
		})
	}
	return rows
}

// prefer is where the prompt's cursor starts. Logins and git signatures come in
// bursts — a push signs more than once — so they start on the session grant;
// arbitrary data starts on the safe default, because nothing about it is
// routine.
func (t target) prefer() prompt.Choice {
	if t.kind == targetArbitrary {
		return prompt.ChoiceDeny
	}
	return prompt.ChoiceAllowSecretSession
}

// userAuthRequest is the data a client signs to log in with a public key
// (RFC 4252 §7): the session identifier, then the request message itself. Rest
// holds the destination's host key for the hostbound method, and must
// otherwise be empty.
type userAuthRequest struct {
	SessionID []byte
	Type      byte
	User      string
	Service   string
	Method    string
	HasSig    bool
	Algorithm string
	PublicKey []byte
	Rest      []byte `ssh:"rest"`
}

// sshsigBlob is the data SSHSIG signs, after the magic preamble.
type sshsigBlob struct {
	Namespace string
	Reserved  string
	HashAlg   string
	Hash      []byte
}

// errWrongSession is the refusal at the heart of this file: a login for a
// session other than the one the connection proved it is for.
var errWrongSession = errors.New("the login is for a different SSH session than the one this connection was bound to")

// targetOf works out what signing data with key would be good for, given the
// binding the connection holds. An error means the request should be refused
// outright, with no policy consulted: it is a login the binding positively
// contradicts, or one that does not describe itself consistently, and neither
// has an honest subject to ask a human about.
func targetOf(key ssh.PublicKey, data []byte, bound destination) (target, error) {
	if login, ok := asUserAuth(data); ok {
		return loginTarget(key, login, bound)
	}
	if namespace, ok := asSSHSIG(data); ok {
		return target{kind: targetSSHSIG, namespace: namespace}, nil
	}
	return target{kind: targetArbitrary}, nil
}

// asUserAuth recognises a public-key login. Anything that starts like one — a
// string and then the request message number — is treated as one, so that a
// request cannot dodge the session check by being slightly malformed.
func asUserAuth(data []byte) (userAuthRequest, bool) {
	var head struct {
		SessionID []byte
		Type      byte
		Rest      []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(data, &head); err != nil || head.Type != msgUserAuthRequest {
		return userAuthRequest{}, false
	}
	var login userAuthRequest
	if err := ssh.Unmarshal(data, &login); err != nil {
		// It claimed to be a login and is not a readable one. Returning it with
		// an empty method gets it refused by loginTarget rather than waved
		// through as arbitrary data.
		return userAuthRequest{SessionID: head.SessionID, Type: head.Type}, true
	}
	return login, true
}

// loginTarget checks a login against the key and the binding, and names where
// it is going.
func loginTarget(key ssh.PublicKey, login userAuthRequest, bound destination) (target, error) {
	if login.Service != userAuthService || !login.HasSig ||
		(login.Method != methodPublicKey && login.Method != methodHostBound) {
		return target{}, errors.New("the data looks like an SSH login but is not a public-key login request")
	}
	if !bytes.Equal(login.PublicKey, key.Marshal()) {
		return target{}, errors.New("the login names a different key from the one asked to sign it")
	}
	var hostKey []byte
	if login.Method == methodHostBound {
		var tail struct {
			HostKey []byte
		}
		if err := ssh.Unmarshal(login.Rest, &tail); err != nil {
			return target{}, errors.New("the hostbound login does not carry a readable host key")
		}
		hostKey = tail.HostKey
	} else if len(login.Rest) != 0 {
		return target{}, errors.New("the login has trailing data")
	}

	switch {
	case bound.hostKey == nil:
		// No bind, or one that could not be believed: the older-ssh case. The
		// subject says the destination is unknown, which no grant for a named
		// destination covers.
		return target{kind: targetLogin}, nil
	case !bytes.Equal(login.SessionID, bound.sessionID):
		if bound.forwarding {
			// The connection was bound for a hop that forwards the agent on,
			// and this login is a further hop out from it (whose ssh did not
			// bind). Where it goes is unknown; that it came through the bound
			// host is not.
			return target{kind: targetLogin, via: bound}, nil
		}
		return target{}, errWrongSession
	case hostKey != nil && !bytes.Equal(hostKey, bound.hostKey.Marshal()):
		return target{}, errors.New("the hostbound login names a different host key from the one this connection was bound to")
	}
	return target{kind: targetLogin, dest: bound}, nil
}

// asSSHSIG recognises an SSHSIG blob and returns its namespace, made safe for a
// subject.
func asSSHSIG(data []byte) (string, bool) {
	rest, ok := bytes.CutPrefix(data, []byte(sshsigMagic))
	if !ok {
		return "", false
	}
	var blob sshsigBlob
	if err := ssh.Unmarshal(rest, &blob); err != nil || blob.Namespace == "" {
		return "", false
	}
	return safeNamespace(blob.Namespace), true
}

// safeNamespace keeps a namespace to characters that cannot change how a
// subject reads or matches: no spaces to fake a " → ", no slash to defeat a
// `*`, no glob metacharacters, no terminal escapes. Real namespaces ("git",
// "file", an email-style "name@example.com") pass through untouched.
func safeNamespace(ns string) string {
	const limit = 64
	var b strings.Builder
	for _, r := range ns {
		if b.Len() >= limit {
			b.WriteString("…")
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_', r == '@', r == '+':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
