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
	// anywhere is making that choice itself, and RemoteAuth says why it sends
	// it as it stands.
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

	// ReasonOutOfScope is a credential this relay knows, used somewhere it does
	// not reach. Separate from bad-credential because the two send an operator
	// to different places: one is a console misconfiguration, the other is a
	// credential on a machine nobody can get to.
	ReasonOutOfScope Reason = "out-of-scope"

	// ReasonEstateWide is a credential that covers a whole estate, refused by a
	// tenant where one estate may hold several customers.
	ReasonEstateWide Reason = "estate-wide-credential"

	// About us, not about the caller. These answer 503, and that difference is
	// the whole point of the type.
	ReasonAuthoriserUnavailable Reason = "authoriser-unavailable"

	// ReasonRevoked is authority withdrawn while something was still open. It
	// answers 401 because it IS about the credential, and it is separate from
	// bad-credential because the credential was good when the poll started and
	// a client that retries with it will be told so.
	ReasonRevoked Reason = "authority-revoked"

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
	case ReasonOutOfScope:
		return "this credential is not scoped to that station and direction"
	case ReasonEstateWide:
		return "this tenant refuses estate-wide credentials"
	case ReasonRevoked:
		return "the authority for this request was withdrawn while it was open"
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

	// MaxBytes caps this one operation, below the server's own limit. Zero
	// means the server's limit, which is MaxBodyBytes.
	//
	// Without this the only lever an operator has over a client posting 8 MiB
	// per message is refusing the account. A per-operation cap is one of the
	// four things a boolean AllowWrite could not express.
	MaxBytes int64

	// Ref identifies whatever the authoriser reserved, and comes back on the
	// Settlement. Opaque here: the relay copies it and never reads it.
	//
	// It exists because admission and accounting are separated in time. Quota
	// has to be reserved before the bytes move and charged after, or two
	// concurrent writes each see room for one and both take it.
	Ref string

	// Scope is what this credential covers, as the authoriser understands it.
	//
	// The relay has already applied it by the time a Grant is returned, so this
	// is not a second gate. It is here so a wrapper can refuse a grant for
	// being too WIDE, which is what Hosted does: a credential covering a whole
	// estate is correct for a self-hoster and is a tenant boundary failure for
	// anybody whose account holds more than one customer.
	Scope Scope
}

// Admission decides whether an attempt may proceed, and reserves what it will
// consume.
//
// Called before a body is read on a write and before a queue is touched on a
// read, so a refusal costs nothing and a reservation is taken before the thing
// it is reserving for happens.
type Admission interface {
	Admit(ctx context.Context, req Request) Grant
}

// Accounting is told what actually happened, after it happened.
//
// Separate from Admission because the two see different numbers. Admission sees
// a declared size, which is what the client said before anything was read;
// charging on that is charging on a number the payer chose. Accounting sees
// what moved.
//
// Settle must not block. It is called on the request path, and an authoriser
// that wants to write a row somewhere should queue it and return.
type Accounting interface {
	Settle(ctx context.Context, s Settlement)
}

// Sessions is the lifecycle of authority that outlives the decision granting
// it.
//
// A long poll is held for 25 seconds by design, and "authorise every call" says
// nothing about a call that is still in progress. Without this, revoking a
// credential means revoked at some point in the next half minute, and the
// person doing the revoking has no way to know when.
type Sessions interface {
	// Watch reports that the authority behind req has ended before its grant
	// would have expired. The relay selects on the returned channel for as long
	// as it is holding something open, and ends it with the Reason received.
	//
	// A nil channel is the correct answer for an authoriser with no revocation
	// to report: it blocks for ever, so nothing is ever revoked mid-flight and
	// nothing is ever woken by accident.
	//
	// ref is the Grant's Ref, so an authoriser can match the watch to whatever
	// it reserved.
	Watch(ctx context.Context, req Request, ref string) <-chan Reason
}

// Authoriser is the whole seam: admission, accounting and session lifecycle.
//
// Three interfaces rather than three loose methods, because they are three
// concerns and an implementation may genuinely care about one. They are
// composed here because the server needs all three, and because the alternative
// is asking whether an authoriser happens to implement Accounting and silently
// skipping it when it does not. A rule that only applies to some implementers
// is not a rule: that mistake is already recorded above the Auth interface, and
// it is not being made twice.
//
// NoAccounting and NoSessions are embeddable for anybody who wants only the
// gate.
//
// heliograph-io/heliograph-cloud#68.
type Authoriser interface {
	Admission
	Accounting
	Sessions
}

// Outcome is what became of an operation.
type Outcome string

const (
	// OutcomeAccepted is a write that was queued.
	OutcomeAccepted Outcome = "accepted"
	// OutcomeDelivered is a read that handed messages over.
	OutcomeDelivered Outcome = "delivered"
	// OutcomeEmpty is a read that found nothing. Accounted anyway: an idle
	// station polls for ever, and a held connection that nobody meters is a
	// cost whose first appearance is the bill.
	OutcomeEmpty Outcome = "empty"
	// OutcomeRefused is an operation the store would not take.
	OutcomeRefused Outcome = "refused"
	// OutcomeRevoked is something ended mid-flight by Sessions.Watch.
	OutcomeRevoked Outcome = "revoked"
)

// Settlement is what an operation actually cost.
//
// The same rule as Request, and for the same reason: routing, counts and an
// outcome. Bytes is a total, not a sample, and there is no field here anybody
// could follow to content.
type Settlement struct {
	// Ref is the Grant's Ref, unchanged.
	Ref      string
	Estate   string
	Station  string
	Dir      string
	Op       Op
	Bytes    int64
	Messages int
	Outcome  Outcome
	At       time.Time
	Started  time.Time
}

// NoAccounting is embeddable by an authoriser with nothing to meter.
type NoAccounting struct{}

// Settle does nothing, which is the honest behaviour for a self-hosted relay
// where there is no bill.
func (NoAccounting) Settle(context.Context, Settlement) {}

// NoSessions is embeddable by an authoriser that never revokes mid-flight.
type NoSessions struct{}

// Watch returns nil, which blocks for ever. See Sessions.Watch.
func (NoSessions) Watch(context.Context, Request, string) <-chan Reason { return nil }

// FromAuth lifts a boolean Auth onto the Authoriser seam.
//
// StaticAuth and anything else a self-hoster wrote keeps working unchanged, and
// gets the distinguishable refusals for free, because the adapter can tell the
// three cases apart by asking twice.
func FromAuth(a Auth) Authoriser { return authAdapter{auth: a} }

type authAdapter struct {
	NoAccounting
	NoSessions
	auth Auth
}

func (ad authAdapter) Admit(_ context.Context, req Request) Grant {
	if req.Credential == "" {
		return Grant{Reason: ReasonNoCredential}
	}
	// A boolean Auth has no notion of a station, so anything it allows is
	// allowed estate-wide. Saying that in the Grant rather than leaving it
	// blank is what lets Hosted refuse it for the right reason.
	wide := Scope{Estate: req.Estate, AllStations: true,
		Read: []string{"c2s", "s2c"}, Write: []string{req.Dir}}
	switch req.Op {
	case OpRead:
		if ad.auth.AllowRead(req.Credential, req.Estate, req.Station, req.Dir) {
			return Grant{Allow: true, Scope: wide}
		}
	case OpWrite:
		if ad.auth.AllowWrite(req.Credential, req.Estate, req.Station, req.Dir) {
			return Grant{Allow: true, Scope: wide}
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
