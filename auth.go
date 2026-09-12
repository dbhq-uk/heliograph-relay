package relay

import (
	"context"
	"net/http"
	"time"
)

// This file is the authorisation seam, and it exists so that the hosted service
// is a caller of this server rather than a fork of it.
//
// The commitment is that the binary in the data path is built from the
// published source with nothing added, so a customer can compare a hash instead
// of trusting an operator. A fork makes that unprovable for ever, and nothing
// in the licence obliges us to avoid one - which is exactly why the discipline
// is written down in CONTRIBUTING.md and why the interface has to be wide
// enough that nobody is ever tempted.
//
// heliograph-io/heliograph-cloud#7.

// Op is what a credential is attempting.
type Op string

const (
	OpRead  Op = "read"
	OpWrite Op = "write"
)

// Request is everything an authoriser is told about an attempt.
//
// Note what is absent, and permanently absent: the message body, any reader
// that could yield one, and the *http.Request it arrived on. An authoriser gets
// routing and a length, and there is no field here it could follow to content.
// Bytes is a size, not a sample.
type Request struct {
	// Credential is the bearer token as presented. An authoriser that sends it
	// anywhere is making that choice itself: RemoteAuth sends a sha256 of it.
	Credential string
	Estate     string
	Station    string
	Dir        string
	Op         Op
	// Bytes is the declared size of the write, from Content-Length, or -1 when
	// the client did not say. Zero on a read.
	Bytes int64
	At    time.Time
}

// Reason says WHY a request was refused, and it is the field that keeps a
// reader on the right side of the gap.
//
// A 401 sends somebody to check a token on a machine they cannot reach. If the
// real fault is that the authoriser is down, that is hours spent on the wrong
// side of the problem, on a transport whose entire proposition is reaching
// machines when things are broken. So the refusal says which, in a status code
// and in a field a program can read.
type Reason string

const (
	// ReasonAllowed is the zero value: nothing was refused.
	ReasonAllowed Reason = ""

	// About the credential. All of these answer 401.
	ReasonNoCredential   Reason = "no-credential"
	ReasonBadCredential  Reason = "bad-credential"
	ReasonWrongDirection Reason = "wrong-direction"

	// About us, not about the caller. These answer 503, and that difference is
	// the whole point of the type.
	ReasonAuthoriserUnavailable Reason = "authoriser-unavailable"

	// About the request or the queue.
	ReasonBadRoute   Reason = "bad-route"
	ReasonUnreadable Reason = "unreadable-request"
	ReasonTooLarge   Reason = "too-large"
	ReasonQueueFull  Reason = "queue-full"
	ReasonInternal   Reason = "internal"
)

// Status is the HTTP code a Reason must produce.
//
// The default is 401 rather than 500, because an unrecognised reason is most
// likely a refusal an authoriser invented, and answering 401 refuses. A default
// that answered 200 would be a hole; a default that answered 503 would tell
// every caller we are broken when we are not.
func (r Reason) Status() int {
	switch r {
	case ReasonAllowed:
		return http.StatusOK
	case ReasonAuthoriserUnavailable:
		return http.StatusServiceUnavailable
	case ReasonQueueFull:
		return http.StatusTooManyRequests
	case ReasonTooLarge:
		return http.StatusRequestEntityTooLarge
	case ReasonBadRoute, ReasonUnreadable:
		return http.StatusBadRequest
	case ReasonInternal:
		return http.StatusInternalServerError
	}
	return http.StatusUnauthorized
}

// Detail is the sentence a client sees when the authoriser supplied none.
//
// Deliberately the same wording the server used before reasons existed, so
// anybody matching on the message string is not broken by a field being added
// beside it.
func (r Reason) Detail() string {
	switch r {
	case ReasonWrongDirection:
		return "not authorised to write that direction for this estate"
	case ReasonAuthoriserUnavailable:
		return "the authoriser could not be reached, so this request was neither allowed nor refused"
	case ReasonBadRoute:
		return "a message must name an estate, a station and a direction of c2s or s2c"
	case ReasonUnreadable:
		return "could not read the message"
	case ReasonTooLarge:
		return ErrTooLarge.Error()
	case ReasonQueueFull:
		return ErrQueueFull.Error()
	case ReasonInternal:
		return "could not accept the message"
	}
	return "not authorised for this estate"
}

// Grant is the answer to a Request, and it is not a boolean.
//
// One round trip has to serve every gate, or the hosted service pays for an
// authorisation call per long poll and still cannot reserve quota. The boolean
// AllowRead/AllowWrite pair below is kept for the self-hosted case, where there
// is nothing to meter and nothing to reserve.
type Grant struct {
	Allow  bool
	Reason Reason
	// Detail, when set, is what the client is told. Safe to return: an
	// authoriser that puts something sensitive here has published it.
	Detail string
}

// Authoriser is the seam the hosted service lives behind.
//
// One method here, deliberately, because heliograph-io/heliograph-cloud#68
// widens it to admission, accounting and session lifecycle and that is a
// different change with a different argument. What is settled now is the shape
// of the answer: a reason rather than a boolean.
type Authoriser interface {
	// Admit is called before a body is read on a write, and before a queue is
	// touched on a read.
	Admit(ctx context.Context, req Request) Grant
}

// FromAuth lifts a boolean Auth onto the Authoriser seam.
//
// StaticAuth and anything else a self-hoster wrote keeps working unchanged, and
// gets the distinguishable refusals for free, because the adapter can tell the
// three cases apart by asking twice.
func FromAuth(a Auth) Authoriser { return authAdapter{a} }

type authAdapter struct{ auth Auth }

func (ad authAdapter) Admit(_ context.Context, req Request) Grant {
	if req.Credential == "" {
		return Grant{Reason: ReasonNoCredential}
	}
	switch req.Op {
	case OpRead:
		if ad.auth.AllowRead(req.Credential, req.Estate, req.Station, req.Dir) {
			return Grant{Allow: true}
		}
	case OpWrite:
		if ad.auth.AllowWrite(req.Credential, req.Estate, req.Station, req.Dir) {
			return Grant{Allow: true}
		}
		// A credential that may READ this queue but not write this direction is
		// a scope refusal, not an unknown credential. Saying which costs one
		// more call against an in-memory map and saves an operator from
		// rotating a token that was never the problem.
		if ad.auth.AllowRead(req.Credential, req.Estate, req.Station, req.Dir) {
			return Grant{Reason: ReasonWrongDirection}
		}
	}
	return Grant{Reason: ReasonBadCredential}
}
