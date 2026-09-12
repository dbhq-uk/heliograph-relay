package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// RemoteAuth asks an authoriser over HTTP, and caches what it hears.
//
// This is how the hosted service adds tenants, estates, quota and billing
// without adding a line to the binary in the data path. It is contributed here
// rather than kept private on purpose: a self-hoster with their own directory
// can point this at it and is not being handed a hollowed-out version of the
// transport. heliograph-io/heliograph-cloud#7.
type RemoteAuth struct {
	// An authoriser reached over HTTP cannot be asked to revoke an open poll:
	// the question travels the wrong way. Embedding NoSessions says so rather
	// than leaving a method somebody assumes does something. Leases carry the
	// revocation instead, in heliograph-io/heliograph-cloud#75.
	NoSessions
	// Nothing is metered here. An authoriser that wants accounting implements
	// Accounting itself and wraps this, or waits for the hosted one that does.
	NoAccounting

	// URL is POSTed a decision request and must answer 200 with a decision.
	// Anything else is an outage, not a refusal. See Admit.
	URL    string
	Client *http.Client

	// Positive is how long a yes is reused, Negative how long a no is.
	//
	// A no expires sooner than a yes because the cost of the two mistakes is
	// not the same: reusing a stale yes keeps a revoked credential alive, and
	// reusing a stale no keeps a repaired one dead. The first is a security
	// problem measured against the second being an availability problem, and on
	// this transport the availability problem is the one that reaches a
	// customer at the worst moment. Neither number removes the trade.
	Positive time.Duration
	Negative time.Duration

	// Now is the clock, for tests.
	Now func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	grant Grant
	until time.Time
}

// NewRemoteAuth returns an authoriser pointed at url, with the defaults.
func NewRemoteAuth(url string) *RemoteAuth {
	return &RemoteAuth{
		URL: url,
		// Short, because this sits in front of every request including a long
		// poll. A slow authoriser must become an outage quickly rather than
		// holding the caller's connection open alongside our own.
		Client:   &http.Client{Timeout: 3 * time.Second},
		Positive: 30 * time.Second,
		Negative: 5 * time.Second,
		Now:      time.Now,
		cache:    map[string]cached{},
	}
}

// decisionRequest is the wire shape, and the field list is the whole of it.
//
// Routing, an operation and a length. No body, no reader, nothing the
// authoriser could follow to content. That is asserted rather than asserted
// about: the conformance suite runs its own control plane, puts a recognisable
// byte pattern through the relay, and fails if the control plane ever saw it.
//
// The credential is sent as presented. Sending a sha256 of it instead would
// mean an authoriser's request log was a list of fingerprints rather than a
// list of live credentials, and that was the first design. It was dropped
// because the Worker cannot hash: `.github/workflows/validate.yml:97` forbids
// cryptography at the edge, so the Worker would have had to send the credential
// raw while the Go server sent a digest. Two implementations disagreeing about
// the wire is a worse fault than the one the digest was fixing, and hand-rolling
// SHA-256 in TypeScript would evade that CI rule rather than satisfy it.
//
// So: an authoriser sees credentials, which is inherent in being the thing that
// decides whether a credential is good. It should hash on receipt and never log
// the field. heliograph-io/heliograph-cloud#75's leases remove the hop entirely,
// which is the actual fix.
type decisionRequest struct {
	Credential string `json:"credential"`
	Estate     string `json:"estate"`
	Station    string `json:"station"`
	Dir        string `json:"dir"`
	Op         string `json:"op"`
	Bytes      int64  `json:"bytes"`
}

type decisionResponse struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

func (a *RemoteAuth) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *RemoteAuth) client() *http.Client {
	if a.Client != nil {
		return a.Client
	}
	return &http.Client{Timeout: 3 * time.Second}
}

// key identifies a decision.
func (r decisionRequest) key() string {
	return r.Credential + "|" + r.Estate + "|" + r.Station + "|" + r.Dir + "|" + r.Op
}

// Admit asks, or answers from cache.
func (a *RemoteAuth) Admit(ctx context.Context, req Request) Grant {
	if req.Credential == "" {
		// No call needed, and no call made: an empty credential is refused here
		// so an unauthenticated flood cannot be turned into a bill.
		return Grant{Reason: ReasonNoCredential}
	}
	dr := decisionRequest{
		Credential: req.Credential,
		Estate:     req.Estate, Station: req.Station, Dir: req.Dir,
		Op: string(req.Op), Bytes: req.Bytes,
	}
	k := dr.key()

	a.mu.Lock()
	if c, ok := a.cache[k]; ok && a.now().Before(c.until) {
		a.mu.Unlock()
		return c.grant
	}
	a.mu.Unlock()

	g, ok := a.ask(ctx, dr)
	if !ok {
		// The authoriser could not be reached, or answered something that was
		// not a decision. Refuse, and say WHICH, because a 401 here sends
		// somebody to check a credential on a machine they cannot reach while
		// the actual fault is on our side of the wire.
		//
		// Not cached. Caching unavailability would extend our outage past its
		// own end, which is the opposite of what the cache is for, and an
		// authoriser that has just come back answers fast anyway.
		return Grant{Reason: ReasonAuthoriserUnavailable}
	}

	ttl := a.Negative
	if g.Allow {
		ttl = a.Positive
	}
	if ttl > 0 {
		a.mu.Lock()
		if a.cache == nil {
			a.cache = map[string]cached{}
		}
		a.cache[k] = cached{grant: g, until: a.now().Add(ttl)}
		a.mu.Unlock()
	}
	return g
}

// ask makes the call. The second return is false when there was no decision to
// be had, which is a different thing from a decision of no.
func (a *RemoteAuth) ask(ctx context.Context, dr decisionRequest) (Grant, bool) {
	payload, err := json.Marshal(dr)
	if err != nil {
		return Grant{}, false
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.URL, bytes.NewReader(payload))
	if err != nil {
		return Grant{}, false
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := a.client().Do(hreq)
	if err != nil {
		return Grant{}, false
	}
	defer func() { _ = resp.Body.Close() }()
	// Only 200 is a decision. A 401 or a 403 from the authoriser is about the
	// relay's own credential to it, and a 500 is about the authoriser, and
	// neither is a statement about the caller. Treating them as refusals is
	// exactly how a deployment fault gets reported as a token fault.
	if resp.StatusCode != http.StatusOK {
		return Grant{}, false
	}
	var out decisionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Grant{}, false
	}
	g := Grant{Allow: out.Allow, Reason: Reason(out.Reason), Detail: out.Detail}
	if !g.Allow && g.Reason == ReasonAllowed {
		// A refusal with no reason would answer 401 by default, which is the
		// right refusal but a poor explanation. Name it.
		g.Reason = ReasonBadCredential
	}
	return g, true
}
