package relay

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// Per-station authorisation, because a credential scoped to an estate is
// scoped to an account, and an account can hold several customers.
//
// The old model is StaticAuth, which is estate-wide in both directions and
// says so: "Either side may read either queue of its own estate". That is right
// for a self-hoster, where one estate is one customer. Put two customers under
// one account and it is a hole: a station credential lifted from a machine at
// customer A reads customer B's queues and writes fabricated replies into B's
// reply queue. Direction restrictions do not provide station isolation, and a
// station name is not a secret.
//
// The fix is that the identifier in the first path segment is minted PER
// STATION at enrolment and kept for that station's life. One identifier per
// account was rejected: the identifier is written into a machine's
// configuration when the operator plants it, so a per-account identifier means
// every reorganisation requires reaching machines nobody can reach. Per station,
// moving a group between accounts is a control-plane record change and no
// machine is ever touched.
//
// heliograph-io/heliograph-cloud#71.

// Scope is what a credential may do, and nothing is permitted by omission.
//
// Every field is a positive grant. An empty Scope allows nothing at all, which
// is the only safe zero value: a scope that matched by leaving a field blank is
// how an estate-wide credential gets into a hosted tenant by accident, and the
// accident is silent until somebody reads somebody else's logs.
type Scope struct {
	// Estate is the identifier in the first path segment.
	//
	// For a hosted tenant this is opaque, minted per station at enrolment, and
	// derived from nothing. The relay treats it as a name and never as a
	// secret: it arrives in a URL, it appears in logs, and everything here
	// works the same if an attacker knows every one of them.
	Estate string

	// Stations this scope covers, by name. A control credential covering a
	// role lists that role's stations.
	Stations []string

	// AllStations makes this scope estate-wide.
	//
	// It exists so an estate-wide credential can SAY so and be refused on that
	// basis, rather than being indistinguishable from a scope nobody filled in.
	// Hosted refuses both, and tells them apart in the sentence it returns.
	AllStations bool

	// Read and Write are the directions permitted, from {"c2s", "s2c"}.
	//
	// Asymmetric on purpose, and the asymmetry survives scoping: a station
	// reads c2s and writes s2c, so it cannot queue a request even for itself.
	Read  []string
	Write []string
}

// permits reports whether this scope covers one attempt.
func (s Scope) permits(estate, station, dir string, op Op) bool {
	if estate == "" || station == "" || !validDir(dir) {
		return false
	}
	if s.Estate == "" || s.Estate != estate {
		return false
	}
	if !s.AllStations && !slices.Contains(s.Stations, station) {
		return false
	}
	switch op {
	case OpRead:
		return slices.Contains(s.Read, dir)
	case OpWrite:
		return slices.Contains(s.Write, dir)
	}
	return false
}

// stationScoped reports whether this scope is narrowed to named stations.
func (s Scope) stationScoped() bool { return !s.AllStations && len(s.Stations) > 0 }

// ScopedAuth holds one scope per credential.
//
// Credentials are keyed by sha256, so a memory dump or a heap profile is a list
// of digests rather than a list of live credentials. There is no constant-time
// compare here and none is needed: the map is keyed by the digest, and
// producing a digest that lands in a bucket requires the credential.
type ScopedAuth struct {
	NoAccounting
	NoSessions

	mu    sync.RWMutex
	scope map[[32]byte]Scope
}

func NewScopedAuth() *ScopedAuth {
	return &ScopedAuth{scope: map[[32]byte]Scope{}}
}

// Add grants a scope to a credential, replacing any it already had.
func (a *ScopedAuth) Add(credential string, s Scope) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.scope[sha256.Sum256([]byte(credential))] = s
}

// Remove withdraws a credential entirely.
//
// This is revocation for a relay holding its own scopes, and it takes effect on
// the next request. It does not reach a poll that is already held: that is what
// Sessions.Watch is for.
func (a *ScopedAuth) Remove(credential string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.scope, sha256.Sum256([]byte(credential)))
}

// Scope returns what a credential may do, and whether it is known at all.
func (a *ScopedAuth) Scope(credential string) (Scope, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	s, ok := a.scope[sha256.Sum256([]byte(credential))]
	return s, ok
}

// Admit enforces the scope.
func (a *ScopedAuth) Admit(_ context.Context, req Request) Grant {
	if req.Credential == "" {
		return Grant{Reason: ReasonNoCredential}
	}
	s, known := a.Scope(req.Credential)
	if !known {
		return Grant{Reason: ReasonBadCredential}
	}
	if s.permits(req.Estate, req.Station, req.Dir, req.Op) {
		return Grant{Allow: true, Scope: s}
	}
	// A credential this relay knows, used somewhere it does not reach. Saying
	// "out-of-scope" rather than "bad-credential" is what stops an operator
	// rotating a credential on a machine they cannot reach for a fault that was
	// a console misconfiguration.
	//
	// It reveals that the credential is valid, which a bad-credential answer
	// would not. That is accepted: the holder of the credential already knows
	// it is valid, and the alternative is an unusable error message for
	// everybody in exchange for nothing against an attacker who has already
	// stolen one.
	return Grant{Reason: ReasonOutOfScope}
}

// Hosted refuses anything it cannot prove is scoped to named stations.
//
// It wraps whatever answers, so an authoriser that was written for a
// self-hosted estate can be pointed at a hosted tenant and will refuse rather
// than quietly authorise one customer against another.
//
// Silence is refused as firmly as an explicit estate-wide grant. An authoriser
// that says "allow" without saying what for has not said the credential is
// station-scoped, and reading silence as the safe answer is how this class of
// hole is created.
type Hosted struct{ Inner Authoriser }

func (h Hosted) Admit(ctx context.Context, req Request) Grant {
	g := h.Inner.Admit(ctx, req)
	if !g.Allow || g.Scope.stationScoped() {
		return g
	}
	detail := "this tenant requires a credential scoped to named stations, and this grant named none"
	if g.Scope.AllStations {
		detail = "this tenant refuses estate-wide credentials, because one account may hold several customers"
	}
	return Grant{Reason: ReasonEstateWide, Detail: detail}
}

func (h Hosted) Settle(ctx context.Context, s Settlement) { h.Inner.Settle(ctx, s) }

func (h Hosted) Watch(ctx context.Context, req Request, ref string) <-chan Reason {
	return h.Inner.Watch(ctx, req, ref)
}

// ParseStationScopes reads per-station scopes from one configuration string.
//
//	estate:station:role:credential, comma separated
//	role is "control" or "station"
//
// The same shape as HELIOGRAPH_RELAY_ESTATES, one level narrower, so a
// self-hoster who wants per-station isolation gets it without running a control
// plane. A control credential covering several stations is listed once per
// station.
//
// Every fault is refused rather than skipped. The Worker used to skip a
// malformed estate, which fails closed and is harder to diagnose than a refusal
// naming the entry.
func ParseStationScopes(spec string) (*ScopedAuth, error) {
	a := NewScopedAuth()
	// roles tracks which roles each credential already has, so one credential
	// cannot be both sides of one station. That collapses the only scope
	// separation there is, exactly as one token for both sides of an estate
	// does, and the Go binary already refuses that at startup.
	roles := map[string]map[string]bool{}

	n := 0
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.Split(entry, ":")
		if len(parts) != 4 {
			return nil, fmt.Errorf("%q is not estate:station:role:credential", entry)
		}
		estate, station, role, credential := parts[0], parts[1], parts[2], parts[3]
		if estate == "" || station == "" || credential == "" {
			return nil, fmt.Errorf("%q leaves estate, station or credential empty, and nothing is permitted by omission", entry)
		}
		var read, write []string
		switch role {
		case "station":
			read, write = []string{"c2s"}, []string{"s2c"}
		case "control":
			read, write = []string{"s2c"}, []string{"c2s"}
		default:
			return nil, fmt.Errorf("%q: role must be \"control\" or \"station\", not %q", entry, role)
		}

		seen := roles[credential]
		if seen == nil {
			seen = map[string]bool{}
			roles[credential] = seen
		}
		for other := range seen {
			if other != role {
				return nil, fmt.Errorf("%q: this credential is already the %s side, and one credential for both sides removes the scope separation entirely", entry, other)
			}
		}
		seen[role] = true

		// A credential listed for several stations covers all of them, which is
		// how a control role spanning a group is expressed.
		s, _ := a.Scope(credential)
		s.Estate, s.Read, s.Write = estate, read, write
		if !slices.Contains(s.Stations, station) {
			s.Stations = append(s.Stations, station)
		}
		a.Add(credential, s)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("no scopes configured, so no client could ever authenticate")
	}
	return a, nil
}
