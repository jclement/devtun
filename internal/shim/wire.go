package shim

// The per-service messages the remote side sends, once the Hello has been
// read and the session has routed the connection.
//
// These are a SECOND SPELLING of one wire format. The first lives with each
// service — `op` in internal/onepassword/wire.go, `open` in
// internal/browser/browser.go — where the types are unexported, because a
// service's own messages are nobody else's business. That privacy is worth the
// copy, but it comes with a rule: the two spellings are one format and must
// change together. The JSON tags are the contract; the Go names are not.

// opKind names the kind of request being made.
//
// The service also understands a ping that never touches the vault. The shim
// has nothing to ping for, so it is not spelled here — an unused constant is
// worse than an absent one, because it looks like a code path.
type opKind string

const (
	// opExec asks the workstation to run `op` with the given arguments.
	opExec opKind = "exec"
	// opResolve asks it to turn a batch of op:// references into their secret
	// values, which is what `op inject` and `op run` need.
	opResolve opKind = "resolve"
)

// opRequest is a single command for the 1Password service.
type opRequest struct {
	Op    opKind   `json:"op"`
	Argv  []string `json:"argv,omitempty"`  // op arguments, without the "op" itself
	Stdin []byte   `json:"stdin,omitempty"` // stdin to hand to op
	Refs  []string `json:"refs,omitempty"`  // op:// references, for opResolve
}

// opResponse is the reply. Exit and the streams mirror the workstation's `op`
// invocation; Error is set only for failures that happened before or instead of
// running op, which is why it is reported separately rather than folded into
// Stderr.
type opResponse struct {
	Exit    int               `json:"exit"`
	Stdout  []byte            `json:"stdout,omitempty"`
	Stderr  []byte            `json:"stderr,omitempty"`
	Error   string            `json:"error,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"` // ref -> value, for opResolve
}

// openRequest asks for a URL to be opened on the workstation. One request, one
// reply, one connection.
type openRequest struct {
	URL string `json:"url"`
}

type openResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}
