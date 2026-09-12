package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// controlPlane is a stand-in for the hosted authoriser: it answers the same
// shape RemoteAuth expects, records what it was asked, and can be taken away.
type controlPlane struct {
	srv *httptest.Server
	// asked records every decision request, so a test can assert what the
	// authoriser was and was not told.
	asked []map[string]any
	// allow decides. Nil means allow everything.
	allow func(map[string]any) (bool, Reason)
}

func newControlPlane(t *testing.T) *controlPlane {
	t.Helper()
	cp := &controlPlane{}
	cp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		cp.asked = append(cp.asked, in)
		allow, reason := true, Reason("")
		if cp.allow != nil {
			allow, reason = cp.allow(in)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"allow": allow, "reason": string(reason)})
	}))
	t.Cleanup(cp.srv.Close)
	return cp
}

// stop takes the control plane away, the way a database failure or a bad
// deployment would.
func (cp *controlPlane) stop() { cp.srv.Close() }

// A control-plane outage must not look like a bad credential.
//
// This is the failure the whole design is arranged around. The reader of a 401
// goes and checks the token on a machine they cannot reach; the reader of a 503
// goes and checks the authoriser, which is the side that is actually broken.
// heliograph-io/heliograph-cloud#7.
func TestAControlPlaneOutageIsNotABadCredential(t *testing.T) {
	cp := newControlPlane(t)
	auth := NewRemoteAuth(cp.srv.URL)
	srv := httptest.NewServer(NewAuthorisingServer(NewStore(), auth, quiet()).Routes())
	t.Cleanup(srv.Close)

	// While the control plane is up, a good credential works.
	if r := put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("x")); r.StatusCode != 202 {
		t.Fatalf("with the control plane up: %d", r.StatusCode)
	}

	cp.stop()

	// A route the relay has never decided before cannot be answered from
	// cache, so this is the outage path.
	r := put(t, srv, "/v1/e1/st2/c2s", "control-token", 1, []byte("x"))
	if r.StatusCode == http.StatusUnauthorized {
		t.Fatal("a control-plane outage answered 401, which sends the reader to the wrong side of the gap")
	}
	if r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 while the authoriser is unreachable, got %d", r.StatusCode)
	}
	var body struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Reason != string(ReasonAuthoriserUnavailable) {
		t.Errorf("refusal reason %q, want %q", body.Reason, ReasonAuthoriserUnavailable)
	}
}

// A refusal the control plane actually made stays a 401. Failing closed must
// not turn every no into "we are broken", or the distinction is worth nothing.
func TestARefusalTheControlPlaneMadeIsStillFourZeroOne(t *testing.T) {
	cp := newControlPlane(t)
	cp.allow = func(map[string]any) (bool, Reason) { return false, ReasonBadCredential }
	auth := NewRemoteAuth(cp.srv.URL)
	srv := httptest.NewServer(NewAuthorisingServer(NewStore(), auth, quiet()).Routes())
	t.Cleanup(srv.Close)

	r := put(t, srv, "/v1/e1/st1/c2s", "wrong", 1, []byte("x"))
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a refused credential should be 401, got %d", r.StatusCode)
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Reason != string(ReasonBadCredential) {
		t.Errorf("refusal reason %q, want %q", body.Reason, ReasonBadCredential)
	}
}

// A refusal that names no reason must still refuse.
//
// This is the hole the outage test found on its way past. The zero value of
// Reason is "allowed", so a Grant{Allow: false} with no reason set took the
// ReasonAllowed branch of Status() and answered 200 with an error body: a
// refusal the caller would read as a success.
func TestARefusalWithNoReasonStillRefuses(t *testing.T) {
	srv := httptest.NewServer(NewAuthorisingServer(NewStore(), silentRefuser{}, quiet()).Routes())
	t.Cleanup(srv.Close)

	r := put(t, srv, "/v1/e1/st1/c2s", "anything", 1, []byte("x"))
	if r.StatusCode == http.StatusOK || r.StatusCode == http.StatusAccepted {
		t.Fatalf("a refusal with no reason answered %d", r.StatusCode)
	}
	if r.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", r.StatusCode)
	}
}

// silentRefuser refuses and says nothing, which is what an authoriser somebody
// else wrote is entitled to do.
type silentRefuser struct {
	NoAccounting
	NoSessions
}

func (silentRefuser) Admit(context.Context, Request) Grant { return Grant{Allow: false} }

// The control plane is told routing, an operation and a length, and that is the
// whole list.
//
// The assertion is on the field SET rather than on the values, because a field
// added later is how a body ends up at an authoriser: somebody adds "payload"
// for a good reason, nothing fails, and the claim that the authoriser never
// touches ciphertext quietly stops being true.
func TestTheControlPlaneIsToldRoutingAndNothingElse(t *testing.T) {
	cp := newControlPlane(t)
	auth := NewRemoteAuth(cp.srv.URL)
	srv := httptest.NewServer(NewAuthorisingServer(NewStore(), auth, quiet()).Routes())
	t.Cleanup(srv.Close)

	secret := []byte("SENTINEL-ciphertext-nobody-should-see")
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, secret)
	if len(cp.asked) == 0 {
		t.Fatal("the control plane was never asked")
	}
	want := map[string]bool{
		"credential": true, "estate": true, "station": true,
		"dir": true, "op": true, "bytes": true,
	}
	for _, q := range cp.asked {
		for k := range q {
			if !want[k] {
				t.Errorf("the control plane was sent an unexpected field %q", k)
			}
		}
		for k := range want {
			if _, ok := q[k]; !ok {
				t.Errorf("the control plane was not sent %q", k)
			}
		}
	}
	// And the bytes themselves never appear, in any field, in any encoding a
	// round trip through JSON would produce.
	raw, _ := json.Marshal(cp.asked)
	for _, form := range []string{string(secret), base64.StdEncoding.EncodeToString(secret)} {
		if bytes.Contains(raw, []byte(form)) {
			t.Fatalf("the message body reached the control plane: %s", raw)
		}
	}
}

// One decision per long poll is one HTTP call per long poll, which is both slow
// and billable. A repeat of the same question inside the TTL must be answered
// from memory.
func TestARepeatedQuestionIsNotAskedTwice(t *testing.T) {
	cp := newControlPlane(t)
	auth := NewRemoteAuth(cp.srv.URL)
	srv := httptest.NewServer(NewAuthorisingServer(NewStore(), auth, quiet()).Routes())
	t.Cleanup(srv.Close)

	for range 5 {
		put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("x"))
	}
	if len(cp.asked) != 1 {
		t.Errorf("asked the control plane %d times for the same decision, want 1", len(cp.asked))
	}
}

// A revoked credential must not stay live because its refusal was cached for
// as long as its approval would have been.
func TestANegativeAnswerIsCachedForLessTimeThanAPositiveOne(t *testing.T) {
	a := NewRemoteAuth("http://example.invalid")
	if !(a.Negative > 0 && a.Negative < a.Positive) {
		t.Errorf("negative TTL %v, positive TTL %v: a no must expire sooner than a yes", a.Negative, a.Positive)
	}
}

// Unavailability is not cached at all. Caching it would extend our outage past
// its own end, which is the opposite of what the cache is for.
func TestUnavailabilityIsNotCached(t *testing.T) {
	cp := newControlPlane(t)
	auth := NewRemoteAuth(cp.srv.URL)
	srv := httptest.NewServer(NewAuthorisingServer(NewStore(), auth, quiet()).Routes())
	t.Cleanup(srv.Close)

	down := auth.URL
	auth.URL = "http://127.0.0.1:1/never" // refused immediately
	if r := put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("x")); r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 while down, got %d", r.StatusCode)
	}
	auth.URL = down
	if r := put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("x")); r.StatusCode != 202 {
		t.Fatalf("the relay was still refusing after the control plane came back: %d", r.StatusCode)
	}
}

// A decision the control plane made before the outage keeps working for as long
// as it was good for. That is the whole reason the cache exists, and it is the
// part heliograph-io/heliograph-cloud#75 extends into leases.
func TestADecisionMadeBeforeTheOutageSurvivesIt(t *testing.T) {
	cp := newControlPlane(t)
	auth := NewRemoteAuth(cp.srv.URL)
	auth.Positive = time.Minute
	srv := httptest.NewServer(NewAuthorisingServer(NewStore(), auth, quiet()).Routes())
	t.Cleanup(srv.Close)

	if r := put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("x")); r.StatusCode != 202 {
		t.Fatalf("with the control plane up: %d", r.StatusCode)
	}
	cp.stop()
	if r := put(t, srv, "/v1/e1/st1/c2s", "control-token", 2, []byte("y")); r.StatusCode != 202 {
		t.Fatalf("a decision made before the outage stopped working during it: %d", r.StatusCode)
	}
}
