package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Two customers under one account, which is the case that breaks the old model.
//
// alpha and bravo are two stations belonging to two different customers of the
// same reseller. Each has its own opaque estate identifier, minted at
// enrolment, and its own credential.
func twoCustomers() *ScopedAuth {
	a := NewScopedAuth()
	a.Add("alpha-station-credential", Scope{
		Estate: "e-9f3c1a", Stations: []string{"pump-01"},
		Read: []string{"c2s"}, Write: []string{"s2c"},
	})
	a.Add("bravo-station-credential", Scope{
		Estate: "e-2b7d44", Stations: []string{"till-07"},
		Read: []string{"c2s"}, Write: []string{"s2c"},
	})
	// One control, covering only alpha's station. The role does not reach
	// bravo, and nothing in the console can make it.
	a.Add("alpha-control-credential", Scope{
		Estate: "e-9f3c1a", Stations: []string{"pump-01"},
		Read: []string{"s2c"}, Write: []string{"c2s"},
	})
	return a
}

func scopedServer(t *testing.T, auth Authoriser) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(NewAuthorisingServer(NewStore(), auth, quiet()).Routes())
	t.Cleanup(srv.Close)
	return srv
}

func reasonOf(t *testing.T, r *http.Response) string {
	t.Helper()
	var why struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&why)
	return why.Reason
}

// A station credential from one customer cannot reach another's queues, and
// this is the test that tries.
//
// The old model was estate-wide in both directions (server.go's StaticAuth:
// "Either side may read either queue of its own estate"). Put two customers
// under one account and mint one estate identifier, and a station credential
// lifted from a machine at customer A reads customer B's queues and writes
// fabricated replies into B's reply queue. Direction restrictions do not provide
// station isolation, and a station identifier is not a secret.
//
// heliograph-io/heliograph-cloud#71.
func TestAStationCredentialCannotReachAnotherCustomer(t *testing.T) {
	srv := scopedServer(t, twoCustomers())

	// Everything alpha's station credential could try against bravo. Both
	// estate identifiers, both station names, both directions, both verbs.
	for _, target := range []string{
		"/v1/e-2b7d44/till-07/c2s", // bravo's requests, with bravo's id
		"/v1/e-2b7d44/till-07/s2c", // bravo's replies
		"/v1/e-9f3c1a/till-07/c2s", // bravo's station name under alpha's id
		"/v1/e-9f3c1a/till-07/s2c",
		"/v1/e-2b7d44/pump-01/c2s", // alpha's station name under bravo's id
		"/v1/e-2b7d44/pump-01/s2c",
	} {
		r := do(t, srv, "GET", target+"?wait=0", "alpha-station-credential", nil)
		if r.StatusCode != 401 {
			t.Errorf("alpha's station credential READ %s: %d", target, r.StatusCode)
		} else if got := reasonOf(t, r); got != string(ReasonOutOfScope) {
			t.Errorf("reading %s was refused as %q, want %q", target, got, ReasonOutOfScope)
		}
		w := put(t, srv, target, "alpha-station-credential", 1, []byte("forged"))
		if w.StatusCode == 202 {
			t.Errorf("alpha's station credential WROTE to %s", target)
		}
	}

	// And it still does its own job, or the test proves only that everything
	// is broken.
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", "alpha-station-credential", 1, []byte("status")); r.StatusCode != 202 {
		t.Fatalf("alpha's station credential could not publish its own status: %d", r.StatusCode)
	}
	if r := do(t, srv, "GET", "/v1/e-9f3c1a/pump-01/c2s?wait=0", "alpha-station-credential", nil); r.StatusCode != 200 {
		t.Fatalf("alpha's station credential could not collect its own requests: %d", r.StatusCode)
	}
}

// A control credential is scoped to the stations its role covers, proved the
// same way.
//
// #71 says this explicitly, because scoping only the station side leaves the
// half that can actually queue a command unbounded, and a command is code
// execution inside somebody else's estate.
func TestAControlCredentialIsScopedToItsOwnStations(t *testing.T) {
	srv := scopedServer(t, twoCustomers())

	for _, target := range []string{
		"/v1/e-2b7d44/till-07/c2s",
		"/v1/e-9f3c1a/till-07/c2s",
		"/v1/e-2b7d44/pump-01/c2s",
	} {
		if r := put(t, srv, target, "alpha-control-credential", 1, []byte("run this")); r.StatusCode == 202 {
			t.Errorf("alpha's control credential queued a command at %s", target)
		}
		if r := do(t, srv, "GET", target+"?wait=0", "alpha-control-credential", nil); r.StatusCode != 401 {
			t.Errorf("alpha's control credential read %s: %d", target, r.StatusCode)
		}
	}

	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/c2s", "alpha-control-credential", 1, []byte("run this")); r.StatusCode != 202 {
		t.Fatalf("alpha's control credential could not queue for its own station: %d", r.StatusCode)
	}
}

// The asymmetry survives per-station scoping. A station credential still may
// not queue a request, even for its own station.
func TestTheDirectionAsymmetrySurvivesScoping(t *testing.T) {
	srv := scopedServer(t, twoCustomers())
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/c2s", "alpha-station-credential", 1, []byte("evil")); r.StatusCode == 202 {
		t.Fatal("a station credential queued a request for its own station")
	}
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", "alpha-control-credential", 1, []byte("fake log")); r.StatusCode == 202 {
		t.Fatal("a control credential published a status as the station")
	}
}

// Nothing is permitted by omission.
//
// A scope that matched by leaving a field blank is how an estate-wide
// credential gets into a hosted tenant by accident, and the accident is silent.
func TestAnEmptyScopePermitsNothing(t *testing.T) {
	a := NewScopedAuth()
	a.Add("empty", Scope{})
	srv := scopedServer(t, a)

	for _, target := range []string{"/v1/e1/st1/c2s", "/v1/e1/st1/s2c", "/v1//st1/c2s", "/v1/e1//c2s"} {
		if r := put(t, srv, target, "empty", 1, []byte("x")); r.StatusCode == 202 {
			t.Errorf("an empty scope permitted a write to %s", target)
		}
		if r := do(t, srv, "GET", target+"?wait=0", "empty", nil); r.StatusCode == 200 {
			t.Errorf("an empty scope permitted a read of %s", target)
		}
	}
}

// A hosted tenant refuses an estate-wide credential, and says which.
//
// StaticAuth is estate-wide by design and correct for the self-hosted case,
// where one estate is one customer. Behind a hosted tenant the same credential
// is the #71 bug, so it is refused rather than trusted, and refused with a
// reason that does not read as "your token is wrong".
func TestAHostedTenantRefusesAnEstateWideCredential(t *testing.T) {
	static := NewStaticAuth()
	static.SetControl("shared-account", "control-token")
	static.SetStation("shared-account", "station-token")
	srv := scopedServer(t, Hosted{Inner: FromAuth(static)})

	r := put(t, srv, "/v1/shared-account/st1/c2s", "control-token", 1, []byte("x"))
	if r.StatusCode == 202 {
		t.Fatal("a hosted tenant accepted an estate-wide credential")
	}
	if got := reasonOf(t, r); got != string(ReasonEstateWide) {
		t.Errorf("refused as %q, want %q", got, ReasonEstateWide)
	}
	if r.StatusCode != 401 {
		t.Errorf("got %d, want 401", r.StatusCode)
	}
}

// And a hosted tenant refuses a credential whose scope was never stated.
//
// An authoriser that answers "allow" without saying what for is not saying the
// credential is station-scoped, and a hosted tenant must not read silence as
// the safe answer.
func TestAHostedTenantRefusesAScopeNobodyStated(t *testing.T) {
	srv := scopedServer(t, Hosted{Inner: alwaysAllow{}})
	r := put(t, srv, "/v1/anything/st1/c2s", "any-credential", 1, []byte("x"))
	if r.StatusCode == 202 {
		t.Fatal("a hosted tenant accepted a grant that stated no scope")
	}
	if got := reasonOf(t, r); got != string(ReasonEstateWide) {
		t.Errorf("refused as %q, want %q", got, ReasonEstateWide)
	}
}

type alwaysAllow struct {
	NoAccounting
	NoSessions
}

func (alwaysAllow) Admit(context.Context, Request) Grant { return Grant{Allow: true} }

// A hosted tenant still allows a properly scoped credential, or the check above
// proves only that hosting is broken.
func TestAHostedTenantAllowsAStationScopedCredential(t *testing.T) {
	srv := scopedServer(t, Hosted{Inner: twoCustomers()})
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/c2s", "alpha-control-credential", 1, []byte("x")); r.StatusCode != 202 {
		t.Fatalf("a hosted tenant refused a station-scoped credential: %d", r.StatusCode)
	}
}

// Moving a group between accounts changes no station configuration.
//
// This is the whole reason the identifier is per station rather than per
// account. A station's configuration is the estate identifier and the
// credential, written into the machine when the operator plants it, and the
// machine is one nobody can reach. So a reorganisation has to be a record
// change on our side and nothing at all on theirs.
//
// The test moves pump-01 from one account to another, which here means the
// authoriser changes its mind about which control credential covers it, and
// asserts that the station's own configuration is untouched and keeps working.
func TestMovingAGroupBetweenAccountsChangesNoStationConfiguration(t *testing.T) {
	const (
		stationEstate = "e-9f3c1a" // written into the machine at plant time
		stationCred   = "alpha-station-credential"
	)
	auth := NewScopedAuth()
	auth.Add(stationCred, Scope{
		Estate: stationEstate, Stations: []string{"pump-01"},
		Read: []string{"c2s"}, Write: []string{"s2c"},
	})
	auth.Add("old-owner-control", Scope{
		Estate: stationEstate, Stations: []string{"pump-01"},
		Read: []string{"s2c"}, Write: []string{"c2s"},
	})
	srv := scopedServer(t, auth)

	// Before: the old owner can reach it, and the station works.
	if r := put(t, srv, "/v1/"+stationEstate+"/pump-01/c2s", "old-owner-control", 1, []byte("before")); r.StatusCode != 202 {
		t.Fatalf("the old owner could not queue: %d", r.StatusCode)
	}
	if r := do(t, srv, "GET", "/v1/"+stationEstate+"/pump-01/c2s?wait=0", stationCred, nil); r.StatusCode != 200 {
		t.Fatalf("the station could not collect: %d", r.StatusCode)
	}

	// The move. A control-plane record change: the old owner's role no longer
	// covers this station, a new owner's does. NOTHING about the station's own
	// configuration is touched, because there is nothing here that could be.
	auth.Remove("old-owner-control")
	auth.Add("new-owner-control", Scope{
		Estate: stationEstate, Stations: []string{"pump-01"},
		Read: []string{"s2c"}, Write: []string{"c2s"},
	})

	// After: the same estate identifier, the same station credential, untouched.
	if r := put(t, srv, "/v1/"+stationEstate+"/pump-01/c2s", "new-owner-control", 1, []byte("after")); r.StatusCode != 202 {
		t.Fatalf("the new owner could not queue after the move: %d", r.StatusCode)
	}
	if r := do(t, srv, "GET", "/v1/"+stationEstate+"/pump-01/c2s?wait=0", stationCred, nil); r.StatusCode != 200 {
		t.Fatalf("the station stopped working after a move it was never told about: %d", r.StatusCode)
	}
	// And the old owner is out, which is the other half of a move.
	if r := put(t, srv, "/v1/"+stationEstate+"/pump-01/c2s", "old-owner-control", 1, []byte("still here?")); r.StatusCode == 202 {
		t.Fatal("the old owner could still queue after the station was moved away")
	}
}

// The scoped configuration a self-hoster writes, parsed from one string.
func TestScopesParseFromConfiguration(t *testing.T) {
	a, err := ParseStationScopes("e-9f3c1a:pump-01:station:alpha-stn, e-9f3c1a:pump-01:control:alpha-ctl")
	if err != nil {
		t.Fatal(err)
	}
	srv := scopedServer(t, a)
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/c2s", "alpha-ctl", 1, []byte("x")); r.StatusCode != 202 {
		t.Errorf("the control credential could not queue: %d", r.StatusCode)
	}
	if r := do(t, srv, "GET", "/v1/e-9f3c1a/pump-01/c2s?wait=0", "alpha-stn", nil); r.StatusCode != 200 {
		t.Errorf("the station credential could not collect: %d", r.StatusCode)
	}
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/c2s", "alpha-stn", 1, []byte("evil")); r.StatusCode == 202 {
		t.Error("a station credential queued a request")
	}
}

func TestBadScopeConfigurationIsRefusedRatherThanIgnored(t *testing.T) {
	for _, spec := range []string{
		"e1:st1:station",              // too few fields
		"e1:st1:wizard:cred",          // not a role
		"e1::station:cred",            // no station
		":st1:station:cred",           // no estate
		"e1:st1:station:",             // no credential
		"e1:st1:station:c,e1:st1:x:c", // the second entry is wrong
	} {
		if _, err := ParseStationScopes(spec); err == nil {
			t.Errorf("%q was accepted", spec)
		}
	}
}

// One credential used for both roles collapses the separation entirely, the
// same way one token for both sides of an estate does.
func TestOneCredentialForBothRolesIsRefused(t *testing.T) {
	_, err := ParseStationScopes("e1:st1:station:same, e1:st1:control:same")
	if err == nil {
		t.Fatal("the same credential was accepted for both roles of one station")
	}
}
