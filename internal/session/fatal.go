package session

import (
	"errors"
	"strings"
)

// Telling a configuration failure apart from a network one.
//
// The supervisor's whole disposition is to keep trying: a laptop sleeps, wifi
// comes and goes, a dev box reboots, and none of that should need a human. But
// that disposition is wrong for a box that will never accept the connection —
// an sshd with forwarding switched off, a user who cannot write to their own
// home directory. Retrying those every thirty seconds for ever looks exactly
// like a hang, and the message that would have explained it scrolls past once
// and is never seen again.
//
// So a small set of failures are classed as permanent and stop the session
// rather than joining the backoff loop. The list is deliberately short: the
// cost of wrongly classing a transient failure as fatal is a session that gives
// up on a box that was about to come back, which is worse than a few extra
// retries. When in doubt, retry.

// fatal marks an error the supervisor should not retry.
type fatal struct{ err error }

func (f fatal) Error() string { return f.err.Error() }
func (f fatal) Unwrap() error { return f.err }

// Fatal wraps err so the session stops instead of reconnecting.
func Fatal(err error) error {
	if err == nil {
		return nil
	}
	return fatal{err}
}

// isFatal reports whether the session should give up.
func isFatal(err error) bool {
	if err == nil {
		return false
	}
	var f fatal
	if errors.As(err, &f) {
		return true
	}
	// sshd refusing the forward is a server configuration decision, not a
	// blip: it will refuse the next attempt for the same reason. The text is
	// matched because x/crypto/ssh reports a refused global request as a bare
	// error with no distinguishing type.
	text := strings.ToLower(err.Error())
	for _, phrase := range []string{
		"allowstreamlocalforwarding",
		"ssh: tcpip-forward request denied",
		"administratively prohibited",
	} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}
