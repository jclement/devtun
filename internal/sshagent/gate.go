package sshagent

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/jclement/devtun/internal/event"
)

// gate is the agent the remote box talks to. It implements the whole
// ExtendedAgent surface so that nothing reaches the real agent except through
// it: a method left out here would be a method x/crypto's server could not
// dispatch, but one left *delegating* would be a hole with no prompt in front
// of it.
//
// There is one gate per forwarded connection, holding one connection to the
// local agent. That is what keeps a destination binding from leaking between
// two `ssh` clients running at once.
type gate struct {
	// ctx bounds every request on this connection. The agent protocol has no
	// context of its own — ServeAgent hands us a method call and nothing else —
	// so it is carried here, and it is what stops a prompt outliving the
	// session that raised it.
	ctx      context.Context
	svc      *Service
	upstream agent.ExtendedAgent
	link     *link

	// dest is what session-bind@openssh.com said this connection is for. No
	// lock guards it: ServeAgent reads and dispatches one request at a time on
	// one goroutine, so the only concurrency is between connections, and those
	// have a gate each.
	dest destination
}

// Sign signs data with the identified key, if policy or a human says so.
func (g *gate) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return g.SignWithFlags(key, data, 0)
}

// SignWithFlags is the gate this service exists for. Everything else in the
// package is arranging for this decision to be made with the right facts.
//
// The flags are passed through untouched: they select rsa-sha2-256 or -512 over
// the legacy ssh-rsa signature, which is the client asking for a *stronger*
// algorithm and nothing devtun should second-guess.
func (g *gate) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	subject := subjectFor(key, g.dest)
	g.link.requested(subject, g.dest)

	allowed, reason := g.svc.authorize(g.ctx, g.link, subject, g.dest)
	if !allowed {
		g.link.denied(subject, reason)
		// The message is for our log, not for the remote: the agent protocol
		// answers a refusal with a bare SSH_AGENT_FAILURE and has nowhere to
		// put a reason. That is a feature here — a remote box learns only that
		// it was refused, not what it would have to say to be allowed.
		return nil, fmt.Errorf("devtun refused this signature: %s", reason)
	}

	started := time.Now()
	signature, err := g.upstream.SignWithFlags(key, data, flags)
	if err != nil {
		g.link.failed("sign", err.Error())
		return nil, err
	}
	g.link.signed(subject, reason, time.Since(started))
	return signature, nil
}

// List hands over which keys are loaded. It is allowed without asking — an
// `ssh` client lists before it signs, and a prompt on every connection attempt
// would be a prompt nobody reads — but it is recorded, because which keys you
// hold is something the remote box now knows and the record should say when it
// learned it.
func (g *gate) List() ([]*agent.Key, error) {
	keys, err := g.upstream.List()
	if err != nil {
		g.link.failed("list", err.Error())
		return nil, err
	}
	g.link.listed(len(keys), g.dest)
	return keys, nil
}

// The mutating half of the agent protocol. None of it consults policy and none
// of it prompts: there is no answer to "may this box delete your keys" worth
// interrupting someone for, and offering the question at all would eventually
// get it answered yes. A refusal is emitted at Warn because, unlike a denied
// signature, nothing legitimate on a dev box asks for these.

func (g *gate) Add(agent.AddedKey) error   { return g.refuse("add a key to") }
func (g *gate) Remove(ssh.PublicKey) error { return g.refuse("remove a key from") }
func (g *gate) RemoveAll() error           { return g.refuse("remove every key from") }
func (g *gate) Lock([]byte) error          { return g.refuse("lock") }
func (g *gate) Unlock([]byte) error        { return g.refuse("unlock") }

// Signers is refused for a different reason from the rest, and it is the
// subtler one: a signer is an ungated signing capability. Handing one back
// would let the holder sign anything, any number of times, with no subject, no
// prompt and no event — every gate in this file bypassed by returning the thing
// they guard.
func (g *gate) Signers() ([]ssh.Signer, error) {
	return nil, g.refuse("take signers out of")
}

// refuse records and explains a refusal. The message never reaches the remote
// box; it is written for the log.
func (g *gate) refuse(what string) error {
	g.link.refused(what, g.dest)
	return fmt.Errorf("devtun will not let a remote host %s your agent", what)
}

// Extension implements session-bind@openssh.com and refuses everything else.
//
// Refusing by default is the point. Extensions are an open-ended command
// channel into the local agent — OpenSSH's own restrict-destination-v00 among
// them, and whatever a particular agent implementation has added — so passing
// them through would be handing the remote box a door this package has not
// looked at. One is implemented because it makes the *prompt* better; the rest
// get the protocol's standard "no".
func (g *gate) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType != sessionBindExtension {
		g.link.refused("use the "+event.SanitizeTo(extensionType, 48)+" extension on", g.dest)
		return nil, agent.ErrExtensionUnsupported
	}

	bind, hostKey, err := parseSessionBind(contents)
	if err != nil {
		// A bind that cannot be read or cannot be believed leaves the
		// connection unbound rather than stale or forged: signatures after this
		// point are attributed to "(destination unknown)", which is the honest
		// answer and still promptable.
		g.dest = destination{}
		g.link.unbound(err)
		return nil, err
	}

	g.dest = g.svc.destinationFor(bind, hostKey)
	g.link.bound(g.dest)
	// An empty response is SSH_AGENT_SUCCESS, which is what `ssh` is waiting
	// for; anything else and it treats the bind as unsupported.
	return nil, nil
}
