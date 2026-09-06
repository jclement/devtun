// Authentication methods.
//
// Everything that authenticates with a key has to live in a *single*
// `publickey` method. x/crypto/ssh records which method *names* it has already
// attempted and never retries one, so a second `ssh.PublicKeys(...)` in the
// list is silently ignored — which looks, from the outside, exactly like the
// agent working and the on-disk keys being ignored.
//
// Within that one method the server is asked about each key in turn before any
// signature is produced, so a key's passphrase is only requested once the
// server has said it will accept that key. That is why encrypted keys become
// deferred signers rather than being unlocked up front.
//
// Order inside the method still matters, because every key offered and refused
// counts against the server's MaxAuthTries: a connection can fail with "no
// supported methods remain" while holding a key that would have worked. So the
// order mirrors ssh(1) — an identity named explicitly goes first, because
// naming one is a statement about which key to use, and otherwise the agent
// goes first, since a key held in an agent (a YubiKey, or one whose passphrase
// you already typed) is far likelier to be live than a forgotten id_rsa from
// years ago. A hardware token never exposes a private key file at all, so the
// agent is the *only* way to authenticate with one.
package sshx

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// defaultKeyNames are the identity files ssh(1) tries when none is configured,
// in the same order.
var defaultKeyNames = []string{
	"id_ed25519",
	"id_ecdsa",
	"id_ecdsa_sk",
	"id_ed25519_sk",
	"id_rsa",
	"id_dsa",
}

// authenticator owns the authentication methods for one connection attempt,
// and the resources behind them.
//
// The agent connection has to outlive the method list — signers borrow it every
// time the server asks for a signature, which for a smartcard is where the PIN
// prompt and the touch happen — but it must not outlive the handshake, or a
// session that reconnects every time the network hiccups leaks a file
// descriptor per attempt until it runs out.
type authenticator struct {
	dest      *Destination
	prompter  Prompter
	agentPath string

	mu        sync.Mutex
	agentConn net.Conn
	sawAgent  bool
	offered   []string
}

func newAuthenticator(d *Destination, o Options) *authenticator {
	return &authenticator{
		dest:      d,
		prompter:  o.Prompter,
		agentPath: resolveAgentPath(o.AuthSock, d.IdentityAgent),
	}
}

// Close releases the agent connection. It is called once the handshake is over,
// after which nothing needs to sign anything again.
func (a *authenticator) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.agentConn == nil {
		return nil
	}
	err := a.agentConn.Close()
	a.agentConn = nil
	return err
}

// usesAgent reports whether any key came from the agent. The caller uses it to
// decide whether a slow handshake is worth explaining — a hardware token
// waiting to be touched is indistinguishable from a hang otherwise.
func (a *authenticator) usesAgent() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sawAgent
}

// offeredCredentials describes, in order, what was presented to the server. It
// is reported back on failure: "the server refused every key" is only useful if
// you can see which keys those were.
func (a *authenticator) offeredCredentials() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.offered...)
}

// methods assembles the authentication methods, in the order OpenSSH would try
// them.
func (a *authenticator) methods() []ssh.AuthMethod {
	methods := []ssh.AuthMethod{ssh.PublicKeysCallback(a.publicKeySigners)}
	if a.prompter == nil {
		return methods
	}
	return append(methods,
		// Keyboard-interactive covers servers that ask for a password this way
		// instead, and simple one-prompt MFA challenges.
		ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i, question := range questions {
				var err error
				if echos[i] {
					answers[i], err = a.prompter.Line(question)
				} else {
					answers[i], err = a.prompter.Secret(question)
				}
				if err != nil {
					return nil, err
				}
			}
			return answers, nil
		}),
		ssh.PasswordCallback(func() (string, error) {
			return a.prompter.Secret(fmt.Sprintf("%s@%s's password: ", a.dest.User, a.dest.Host))
		}),
	)
}

// publicKeySigners gathers every key we could authenticate with. A key that
// cannot be loaded is skipped rather than fatal — one stale IdentityFile line
// should not stop the others being tried.
func (a *authenticator) publicKeySigners() ([]ssh.Signer, error) {
	// An identity named in the configuration is a deliberate choice; the
	// defaults found by scanning ~/.ssh are just what happens to be there.
	named := len(a.dest.IdentityFiles) > 0
	keyFiles := a.dest.IdentityFiles
	if !named {
		keyFiles = discoverKeys()
	}

	var agentKeys []ssh.Signer
	var agentBlobs map[string]bool
	var agentErr error
	if !a.dest.IdentitiesOnly {
		agentKeys, agentBlobs, agentErr = a.agentSigners()
	}

	var fileKeys []ssh.Signer
	var fileNames []string
	for _, path := range keyFiles {
		// Offering a key the agent already holds wastes an attempt on a
		// credential that is about to be offered anyway.
		if !named && agentHasKeyFor(agentBlobs, path) {
			continue
		}
		signer, err := loadIdentity(path, a.prompter)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				notify(a.prompter, fmt.Sprintf("skipping %s: %v", path, err))
			}
			continue
		}
		fileKeys = append(fileKeys, signer)
		fileNames = append(fileNames, path)
	}

	var signers []ssh.Signer
	var offered []string
	addAgent := func() {
		if len(agentKeys) == 0 {
			return
		}
		signers = append(signers, agentKeys...)
		offered = append(offered, fmt.Sprintf("agent (%d key%s)", len(agentKeys), plural(len(agentKeys))))
	}
	addFiles := func() {
		signers = append(signers, fileKeys...)
		offered = append(offered, fileNames...)
	}
	if named {
		addFiles()
		addAgent()
	} else {
		addAgent()
		addFiles()
	}

	a.mu.Lock()
	a.offered = offered
	a.mu.Unlock()

	if len(signers) == 0 {
		switch {
		case a.dest.IdentitiesOnly:
			return nil, errors.New("no usable SSH keys: no configured identity file could be loaded, and IdentitiesOnly rules out the agent")
		case agentErr != nil:
			return nil, fmt.Errorf("no usable SSH keys: no identity file could be loaded, and the agent was unavailable (%w)", agentErr)
		default:
			return nil, errors.New("no usable SSH keys: the agent offered none, and no identity file could be loaded")
		}
	}
	return signers, nil
}

// agentSigners talks to the running SSH agent, returning its signers and the
// public keys it holds. The connection is kept open for the life of the
// handshake because every signature goes back through it.
func (a *authenticator) agentSigners() ([]ssh.Signer, map[string]bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.agentPath == "" {
		return nil, nil, errors.New("no SSH agent configured (SSH_AUTH_SOCK is unset)")
	}
	if a.agentConn == nil {
		conn, err := dialAgentAt(a.agentPath)
		if err != nil {
			return nil, nil, fmt.Errorf("connecting to the SSH agent at %s: %w", a.agentPath, err)
		}
		a.agentConn = conn
	}

	client := agent.NewClient(a.agentConn)
	blobs := agentPublicKeys(client)
	signers, err := agentKeySigners(client)
	if err != nil {
		return nil, blobs, fmt.Errorf("listing keys from the SSH agent: %w", err)
	}
	if len(signers) > 0 {
		a.sawAgent = true
	}
	return signers, blobs, nil
}

// agentKeySigners fetches the agent's signers, retrying once if the first
// attempt comes back empty or failing.
//
// This is not defensive padding. gpg-agent backed by a smartcard — a YubiKey —
// can answer the first identity request before it has scanned the card, giving
// back an error or an empty list. Offering nothing makes the publickey method
// fail outright, and the connection dies with "no supported methods remain"
// while the key that would have worked sits in the agent.
func agentKeySigners(ag agent.ExtendedAgent) ([]ssh.Signer, error) {
	signers, err := ag.Signers()
	if err == nil && len(signers) > 0 {
		return signers, nil
	}
	retry, retryErr := ag.Signers()
	if retryErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, retryErr
	}
	return retry, nil
}

// agentPublicKeys indexes the public keys an agent is holding. Listing does not
// touch the hardware; only signing does, so this is safe with a YubiKey. It
// doubles as the first request that wakes a smartcard-backed agent.
func agentPublicKeys(ag agent.ExtendedAgent) map[string]bool {
	keys, err := ag.List()
	if err != nil || len(keys) == 0 {
		if keys, err = ag.List(); err != nil {
			return nil
		}
	}
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[string(k.Marshal())] = true
	}
	return out
}

// agentHasKeyFor reports whether the agent already holds the key whose public
// half sits beside the given private key file.
func agentHasKeyFor(blobs map[string]bool, privatePath string) bool {
	if len(blobs) == 0 {
		return false
	}
	data, err := os.ReadFile(privatePath + ".pub")
	if err != nil {
		return false
	}
	public, _, _, _, err := ssh.ParseAuthorizedKey(bytes.TrimSpace(data))
	if err != nil {
		return false
	}
	return blobs[string(public.Marshal())]
}

// discoverKeys returns the default identity files that exist. Unlike a
// configured IdentityFile, these were never asked for by name, so one that is
// absent is not worth mentioning.
func discoverKeys() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var out []string
	for _, name := range defaultKeyNames {
		p := filepath.Join(home, ".ssh", name)
		if fileExists(p) {
			out = append(out, p)
		}
	}
	return out
}

// resolveAgentPath decides which agent to talk to: an explicit override first,
// then ssh_config's IdentityAgent, then the environment. `none` disables the
// agent, and `SSH_AUTH_SOCK` means "the environment", both as ssh_config
// defines them.
func resolveAgentPath(explicit, fromConfig string) string {
	for _, candidate := range []string{explicit, fromConfig} {
		candidate = strings.Trim(strings.TrimSpace(candidate), `"`)
		switch {
		case candidate == "":
			continue
		case strings.EqualFold(candidate, "none"):
			return ""
		case candidate == "SSH_AUTH_SOCK":
			return os.Getenv("SSH_AUTH_SOCK")
		default:
			return ExpandPath(candidate)
		}
	}
	if fromEnvironment := os.Getenv("SSH_AUTH_SOCK"); fromEnvironment != "" {
		return fromEnvironment
	}
	return defaultAgentPath()
}

// loadIdentity turns a private key file into a signer. Unencrypted keys are
// parsed immediately; encrypted ones become a deferredKey so that the
// passphrase prompt only happens if the server accepts that key.
func loadIdentity(path string, prompter Prompter) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(data)
	if err == nil {
		return signer, nil
	}

	var needsPassphrase *ssh.PassphraseMissingError
	if !errors.As(err, &needsPassphrase) {
		return nil, fmt.Errorf("loading key %s: %w", path, err)
	}
	if prompter == nil {
		return nil, fmt.Errorf("key %s is encrypted: %w", path, ErrNoTerminal)
	}

	public := needsPassphrase.PublicKey
	if public == nil {
		public = readPublicKeyFile(path + ".pub")
	}
	if public == nil {
		// Without the public key there is nothing to offer the server, so the
		// passphrase has to be asked for now.
		return unlockKey(path, data, prompter)
	}
	return &deferredKey{path: path, data: data, public: public, prompter: prompter}, nil
}

// deferredKey offers a public key to the server and only unlocks the private
// key if the server says it will accept it.
type deferredKey struct {
	path     string
	data     []byte
	public   ssh.PublicKey
	prompter Prompter

	once   sync.Once
	signer ssh.Signer
	err    error
}

// PublicKey returns the offered key.
func (d *deferredKey) PublicKey() ssh.PublicKey { return d.public }

// Sign unlocks the key if needed and signs.
func (d *deferredKey) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	signer, err := d.load()
	if err != nil {
		return nil, err
	}
	return signer.Sign(rand, data)
}

// SignWithAlgorithm forwards the requested signature algorithm. Implementing
// this matters for RSA keys: without it the connection is limited to the
// deprecated ssh-rsa algorithm, which modern servers refuse.
func (d *deferredKey) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	signer, err := d.load()
	if err != nil {
		return nil, err
	}
	if algorithmSigner, ok := signer.(ssh.AlgorithmSigner); ok {
		return algorithmSigner.SignWithAlgorithm(rand, data, algorithm)
	}
	if algorithm != "" && algorithm != signer.PublicKey().Type() {
		return nil, fmt.Errorf("key %s cannot sign with %s", d.path, algorithm)
	}
	return signer.Sign(rand, data)
}

func (d *deferredKey) load() (ssh.Signer, error) {
	d.once.Do(func() { d.signer, d.err = unlockKey(d.path, d.data, d.prompter) })
	return d.signer, d.err
}

// unlockKey asks for a passphrase and parses the key with it.
func unlockKey(path string, data []byte, prompter Prompter) (ssh.Signer, error) {
	if prompter == nil {
		return nil, fmt.Errorf("key %s is encrypted: %w", path, ErrNoTerminal)
	}
	passphrase, err := prompter.Secret(fmt.Sprintf("Enter passphrase for key %s: ", path))
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("unlocking key %s: %w", path, err)
	}
	return signer, nil
}

// readPublicKeyFile loads the companion .pub file, which OpenSSH writes beside
// every key it generates.
func readPublicKeyFile(path string) ssh.PublicKey {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	public, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil
	}
	return public
}

// authHint adds guidance to an authentication failure, which is otherwise one
// of the least actionable errors SSH produces.
func authHint(err error, d *Destination, offered []string) string {
	if !strings.Contains(err.Error(), "unable to authenticate") {
		return ""
	}
	hint := "\n\nThe server refused every credential offered, in this order:"
	if len(offered) == 0 {
		hint += "\n  (none)"
	}
	for _, o := range offered {
		hint += "\n  - " + o
	}
	if d.IdentitiesOnly {
		hint += "\n\nThe agent was not consulted: naming a key with -i, or IdentitiesOnly in" +
			"\nssh_config, restricts devtun to the keys named there."
	} else {
		hint += "\n\nAgent keys are offered first, then the ~/.ssh defaults."
	}
	hint += "\nIf `ssh " + d.Label() + "` works, check that the agent holding that key is"
	hint += "\nreachable here (ssh-add -l), or name the key directly with -i."
	return hint
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
