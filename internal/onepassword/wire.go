package onepassword

// The wire between the shim's `op` impersonation on the remote box and this
// service.
//
// These types are one of TWO spellings of a single wire format. The other lives
// in internal/shim/wire.go, which is the remote half, and the two must change
// together — the JSON tags here are the contract. They are deliberately not a
// shared package: that would couple every service to every other one through a
// common types import, and the point of the Hello envelope is that each service
// owns its own messages. The framing and the Hello envelope belong to internal/shim, because
// every service speaks them; what is left here is the pair of messages only
// this service understands.
//
// The session has already read the Hello and routed on it, so a request says
// nothing about who is asking: the caller arrives out of band, from a
// connection devtun authenticated, rather than from a body the remote box
// composed.

// opKind names the kind of request being made.
type opKind string

const (
	// opExec asks the workstation to run `op` with the given arguments.
	opExec opKind = "exec"
	// opResolve asks it to turn a batch of op:// references into their secret
	// values. The shim uses it for `op inject` and `op run`, where a single
	// template may mention a dozen references and prompting once per reference
	// would be unusable.
	opResolve opKind = "resolve"
	// opPing is a liveness check that never touches the vault.
	opPing opKind = "ping"
)

// opRequest is a single command from the shim.
type opRequest struct {
	Op    opKind   `json:"op"`
	Argv  []string `json:"argv,omitempty"`  // op arguments, without the "op" itself
	Stdin []byte   `json:"stdin,omitempty"` // stdin to hand to op
	Refs  []string `json:"refs,omitempty"`  // op:// references, for opResolve
}

// opResponse is the reply. Exit and the streams mirror the local `op`
// invocation; Error is set only for failures that happened before or instead of
// running op (denied by policy, blocked by the guard, op not installed).
type opResponse struct {
	Exit    int               `json:"exit"`
	Stdout  []byte            `json:"stdout,omitempty"`
	Stderr  []byte            `json:"stderr,omitempty"`
	Error   string            `json:"error,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"` // ref -> value, for opResolve
}
