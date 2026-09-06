package tunnels

import (
	"bytes"
)

// Scheme is what a forwarded port turns out to speak. It decides the URL the
// `o` and space keys open, and is remembered per host and port between runs.
type Scheme string

const (
	// SchemeUnknown means we have not been told and could not tell. Interactive
	// opening asks the user, while raw output exposes only the host:port endpoint.
	SchemeUnknown Scheme = ""
	SchemeHTTP    Scheme = "http"
	SchemeHTTPS   Scheme = "https"
)

// schemeCycle is the order the `t` key steps through.
var schemeCycle = []Scheme{SchemeUnknown, SchemeHTTP, SchemeHTTPS}

// Next returns the following scheme in the cycle.
func (s Scheme) Next() Scheme {
	for i, c := range schemeCycle {
		if c == s {
			return schemeCycle[(i+1)%len(schemeCycle)]
		}
	}
	return SchemeHTTP
}

// ParseScheme validates a remembered value.
func ParseScheme(s string) Scheme {
	switch Scheme(s) {
	case SchemeHTTP:
		return SchemeHTTP
	case SchemeHTTPS:
		return SchemeHTTPS
	default:
		return SchemeUnknown
	}
}

// URLScheme returns the scheme to build a URL with. Callers must handle unknown
// before using it; the fallback keeps the zero value harmless internally.
func (s Scheme) URLScheme() string {
	if s == SchemeHTTPS {
		return "https"
	}
	return "http"
}

// Label renders the scheme for the table: plainly "unknown", "http" or
// "https", rather than punctuation the reader has to decode.
func (s Scheme) Label() string {
	if s == SchemeUnknown {
		return "unknown"
	}
	return string(s)
}

// SniffScheme classifies a service from the first bytes it sends in reply.
//
// This is deliberately passive. Actively probing means opening a connection and
// speaking a protocol at whatever is listening: a TLS ClientHello arrives at a
// plain HTTP server as a line of binary garbage, and the server logs it as a
// malformed request. Watching bytes that were going to cross the tunnel anyway
// costs nothing and startles nobody.
//
// A TLS server opens with a handshake record (0x16) or an alert (0x15) — the
// alert being what it sends when a browser speaks plaintext at it, which is
// exactly the case worth catching. An HTTP server opens with its status line.
func SniffScheme(b []byte) Scheme {
	if len(b) == 0 {
		return SchemeUnknown
	}
	switch b[0] {
	case 0x16, 0x15: // TLS handshake, TLS alert
		return SchemeHTTPS
	}
	if bytes.HasPrefix(b, []byte("HTTP/")) {
		return SchemeHTTP
	}
	return SchemeUnknown
}
