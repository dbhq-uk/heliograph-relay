package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Leased collection, which exists because delete-on-collection has a loss window
// in it.
//
// Take used to return a queue and delete it in the same breath. The comment
// defending that said a client which crashes between reading and processing "can
// simply ask for the step again" - except it cannot, because the message is
// already gone. The window between the relay's delete and the collector's durable
// write is somebody's only copy of a capture.
//
// heliograph-io/heliograph-cloud#9.

type leaseReply struct {
	Lease string `json:"lease"`
	// A string, not a time.Time, because an empty leased collection answers
	// "until":"" - the same as the Worker, which is the point. Decoding into a
	// time.Time would fail on the empty case and hide the agreement.
	Until    string    `json:"until"`
	Messages []Message `json:"messages"`
}

func lease(t *testing.T, srv *httptest.Server, path, tok string) leaseReply {
	t.Helper()
	r := do(t, srv, "GET", path, tok, nil)
	if r.StatusCode != 200 {
		t.Fatalf("lease %s: %d", path, r.StatusCode)
	}
	var got leaseReply
	if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
		t.Fatalf("lease %s: %v", path, err)
	}
	return got
}

func ack(t *testing.T, srv *httptest.Server, path, tok, id string) *http.Response {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"lease": id})
	return do(t, srv, "POST", path, tok, b)
}

func bodies(msgs []Message) []string {
	out := make([]string, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, string(m.Body))
	}
	return out
}

// The compatibility guarantee, and the one that stops this breaking every station
// already deployed: without ?lease= nothing changes at all.
func TestCollectingWithoutALeaseBehavesExactlyAsBefore(t *testing.T) {
	srv, st := newTestServer(t)
	for _, b := range []string{"one", "two", "three"} {
		put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte(b))
	}

	r := do(t, srv, "GET", "/v1/e1/st1/c2s?wait=0", "station-token", nil)
	// A bare array, not an object. A station parsing this with jq '.[]' must not
	// have to know that leasing exists.
	var got []Message
	if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
		t.Fatalf("the response is no longer a bare array of messages: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d messages, want 3", len(got))
	}
	if want := []string{"one", "two", "three"}; !equalStrings(bodies(got), want) {
		t.Errorf("got %v, want %v", bodies(got), want)
	}
	// And they are gone, because collection without a lease still deletes.
	if d := st.Depth("e1", "st1", "c2s"); d != 0 {
		t.Errorf("a collection without a lease left %d message(s) behind", d)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestALeasedMessageIsHeldUntilItIsAcknowledged(t *testing.T) {
	srv, st := newTestServer(t)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("only copy"))

	held := lease(t, srv, "/v1/e1/st1/c2s?wait=0&lease=30s", "station-token")
	if len(held.Messages) != 1 {
		t.Fatalf("leased %d messages, want 1", len(held.Messages))
	}
	if held.Lease == "" {
		t.Fatal("no lease id came back, so nothing can be acknowledged")
	}
	if held.Until == "" {
		t.Error("no deadline came back, so a collector cannot tell how long it has")
	}
	if _, err := time.Parse(time.RFC3339Nano, held.Until); err != nil {
		t.Errorf("the deadline is not a timestamp a client can parse: %q", held.Until)
	}
	// Still on the relay: this is the whole point. The collector has not said it
	// has it yet.
	if d := st.Depth("e1", "st1", "c2s"); d != 1 {
		t.Errorf("the relay deleted a leased message: depth %d", d)
	}

	r := ack(t, srv, "/v1/e1/st1/c2s/ack", "station-token", held.Lease)
	if r.StatusCode != 200 {
		t.Fatalf("ack: %d", r.StatusCode)
	}
	var acked struct {
		Deleted int `json:"deleted"`
	}
	_ = json.NewDecoder(r.Body).Decode(&acked)
	if acked.Deleted != 1 {
		t.Errorf("ack deleted %d, want 1", acked.Deleted)
	}
	if d := st.Depth("e1", "st1", "c2s"); d != 0 {
		t.Errorf("an acknowledged message is still queued: depth %d", d)
	}
}

// The assertion the issue is named for: a collector that dies before
// acknowledging finds the messages again.
func TestACollectorThatDiesBeforeAcknowledgingFindsTheMessagesAgain(t *testing.T) {
	st := NewStore()
	now := time.Now()
	st.now = func() time.Time { return now }
	srv := httptest.NewServer(NewServer(st, testAuth(), quiet()).Routes())
	t.Cleanup(srv.Close)

	put(t, srv, "/v1/e1/st1/c2s", "control-token", 7, []byte("an hour of capture"))
	held := lease(t, srv, "/v1/e1/st1/c2s?wait=0&lease=30s", "station-token")
	if len(held.Messages) != 1 {
		t.Fatalf("leased %d, want 1", len(held.Messages))
	}

	// The collector dies here. No ack, ever.

	// Before the lease expires, nobody else gets it: two collectors racing for the
	// same queue is what the lease exists to stop.
	again := lease(t, srv, "/v1/e1/st1/c2s?wait=0&lease=30s", "station-token")
	if len(again.Messages) != 0 {
		t.Errorf("a live lease was handed to a second collector: %d messages", len(again.Messages))
	}

	now = now.Add(31 * time.Second)

	back := lease(t, srv, "/v1/e1/st1/c2s?wait=0&lease=30s", "station-token")
	if len(back.Messages) != 1 {
		t.Fatalf("the messages did not come back after the lease expired: %d", len(back.Messages))
	}
	if !bytes.Equal(back.Messages[0].Body, []byte("an hour of capture")) {
		t.Errorf("a different message came back: %q", back.Messages[0].Body)
	}
	// The same id, which is what lets a collector recognise a retry rather than
	// treating it as a second message. Without this, deduplication at the
	// collector has nothing to key on.
	if back.Messages[0].ID != held.Messages[0].ID {
		t.Errorf("the redelivered message has a new id: %q then %q",
			held.Messages[0].ID, back.Messages[0].ID)
	}
	if back.Lease == held.Lease {
		t.Errorf("the second collection reused the expired lease id %q", back.Lease)
	}
}

// A message under lease is invisible to a collector that did not ask for one.
// Without this the lease guarantees nothing: any old client could take the
// message out from under the collector holding it.
func TestALeasedMessageIsInvisibleToANonLeasingCollector(t *testing.T) {
	srv, _ := newTestServer(t)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("leased"))
	held := lease(t, srv, "/v1/e1/st1/c2s?wait=0&lease=30s", "station-token")
	if len(held.Messages) != 1 {
		t.Fatalf("leased %d, want 1", len(held.Messages))
	}

	r := do(t, srv, "GET", "/v1/e1/st1/c2s?wait=0", "station-token", nil)
	var got []Message
	_ = json.NewDecoder(r.Body).Decode(&got)
	if len(got) != 0 {
		t.Errorf("a plain collection took %d message(s) held under a lease", len(got))
	}
}

// Two collectors on one queue get disjoint sets, in order, and each can
// acknowledge only its own.
func TestTwoLeasesDoNotOverlap(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, b := range []string{"a", "b", "c", "d"} {
		put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte(b))
	}

	first := lease(t, srv, "/v1/e1/st1/c2s?wait=0&lease=30s&limit=2", "station-token")
	second := lease(t, srv, "/v1/e1/st1/c2s?wait=0&lease=30s&limit=2", "station-token")

	if !equalStrings(bodies(first.Messages), []string{"a", "b"}) {
		t.Errorf("first collector got %v", bodies(first.Messages))
	}
	if !equalStrings(bodies(second.Messages), []string{"c", "d"}) {
		t.Errorf("second collector got %v", bodies(second.Messages))
	}
	if first.Lease == second.Lease {
		t.Fatal("both collectors were given the same lease id")
	}

	if r := ack(t, srv, "/v1/e1/st1/c2s/ack", "station-token", first.Lease); r.StatusCode != 200 {
		t.Fatalf("first ack: %d", r.StatusCode)
	}
	// The second collector's messages are untouched by the first one's ack.
	still := lease(t, srv, "/v1/e1/st1/c2s?wait=0&lease=30s", "station-token")
	if len(still.Messages) != 0 {
		t.Errorf("the first ack released %d of the second collector's messages", len(still.Messages))
	}
}

// An ack for a lease the relay does not hold is 410 rather than 404, because the
// route exists and the lease is what is gone. Either way a collector's safe
// response is the same: assume the messages will be redelivered.
func TestAcknowledgingALeaseTheRelayDoesNotHoldIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("x"))
	held := lease(t, srv, "/v1/e1/st1/c2s?wait=0&lease=30s", "station-token")

	if r := ack(t, srv, "/v1/e1/st1/c2s/ack", "station-token", "not-a-lease"); r.StatusCode != http.StatusGone {
		t.Errorf("ack of an unknown lease: got %d, want 410", r.StatusCode)
	}
	if r := ack(t, srv, "/v1/e1/st1/c2s/ack", "station-token", held.Lease); r.StatusCode != 200 {
		t.Fatalf("ack: %d", r.StatusCode)
	}
	// And the same ack again, which is what a collector retrying a request whose
	// response it never saw will send.
	if r := ack(t, srv, "/v1/e1/st1/c2s/ack", "station-token", held.Lease); r.StatusCode != http.StatusGone {
		t.Errorf("a repeated ack: got %d, want 410", r.StatusCode)
	}
}

// Acknowledging is part of collecting, so it takes the read scope. A station
// token may acknowledge the requests it collects, and may still not queue one.
func TestAcknowledgingNeedsTheSameScopeAsCollecting(t *testing.T) {
	srv, _ := newTestServer(t)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("x"))
	held := lease(t, srv, "/v1/e1/st1/c2s?wait=0&lease=30s", "station-token")

	if r := ack(t, srv, "/v1/e1/st1/c2s/ack", "", held.Lease); r.StatusCode != 401 {
		t.Errorf("ack with no token: %d", r.StatusCode)
	}
	if r := ack(t, srv, "/v1/e1/st1/c2s/ack", "other-station", held.Lease); r.StatusCode != 401 {
		t.Errorf("ack with another estate's token: %d", r.StatusCode)
	}
	if r := ack(t, srv, "/v1/e1/st1/c2s/ack", "station-token", held.Lease); r.StatusCode != 200 {
		t.Errorf("ack with the collecting token: %d", r.StatusCode)
	}
	// Unchanged, and checked here because the ack route sits under the same path
	// as the put: a station still may not queue a request.
	if r := put(t, srv, "/v1/e1/st1/c2s", "station-token", 1, []byte("evil")); r.StatusCode == 202 {
		t.Error("a station token queued a request through the leasing change")
	}
}

// ParseLease is asserted on its own as well as through a request, because the
// first version applied the ceiling only to durations with a unit: lease=600 went
// through as ten minutes. The request still failed, because TakeLeased checks the
// bound too, and a rule enforced in one place out of two is a rule that will be
// moved to the wrong place eventually.
func TestParseLeaseAppliesTheCeilingToEveryForm(t *testing.T) {
	for _, v := range []string{"600", "6m", "1h", "301s"} {
		if _, err := ParseLease(v); err == nil {
			t.Errorf("ParseLease(%q) allowed a lease longer than %s", v, MaxLease)
		}
	}
	for _, v := range []string{"30", "30s", "300s", "500ms", "0.5s", "2m"} {
		if _, err := ParseLease(v); err != nil {
			t.Errorf("ParseLease(%q): %v", v, err)
		}
	}
	// One grammar, small enough that the Worker implements the same one rather
	// than a near-miss. Go's own ParseDuration accepts compound durations, and
	// inheriting that quirk here would mean ?lease=1m30s worked against one
	// implementation and not the other.
	for _, v := range []string{"1m30s", "30 s", "s30", "3d", "nonsense", "-5s", "1e2s"} {
		if _, err := ParseLease(v); err == nil {
			t.Errorf("ParseLease(%q) was accepted, so the two implementations can disagree about it", v)
		}
	}
	for _, v := range []string{"", "0"} {
		d, err := ParseLease(v)
		if err != nil || d != 0 {
			t.Errorf("ParseLease(%q) = %v, %v; want no lease and no error", v, d, err)
		}
	}
}

func TestALeaseThatIsTooLongOrNotADurationIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("x"))

	for _, q := range []string{"lease=nonsense", "lease=1h", "lease=-5s", "lease=600"} {
		r := do(t, srv, "GET", "/v1/e1/st1/c2s?wait=0&"+q, "station-token", nil)
		if r.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", q, r.StatusCode)
		}
	}
	// Bare seconds, because a query parameter written by hand in a shell script
	// should not need a unit to be understood.
	if got := lease(t, srv, "/v1/e1/st1/c2s?wait=0&lease=30", "station-token"); len(got.Messages) != 1 {
		t.Errorf("lease=30 leased %d messages", len(got.Messages))
	}
}

// lease=0 is not a lease. It means what its absence means, so a client that
// builds its query string from a variable does not accidentally change
// semantics when the variable is empty.
func TestLeaseZeroIsTheOldBehaviour(t *testing.T) {
	srv, st := newTestServer(t)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("x"))

	r := do(t, srv, "GET", "/v1/e1/st1/c2s?wait=0&lease=0", "station-token", nil)
	var got []Message
	if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
		t.Fatalf("lease=0 did not answer with a bare array: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("lease=0 returned %d messages", len(got))
	}
	if d := st.Depth("e1", "st1", "c2s"); d != 0 {
		t.Errorf("lease=0 held the message rather than deleting it: depth %d", d)
	}
}

// Durability and leasing have to agree about when a message is gone: the durable
// copy goes on acknowledgement, and not before.
func TestAcknowledgingDeletesTheSpooledCopyAndALeaseDoesNot(t *testing.T) {
	dir := t.TempDir()
	srv, _ := spooled(t, dir)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("only copy"))

	held := lease(t, srv, "/v1/e1/st1/c2s?wait=0&lease=30s", "station-token")
	if len(held.Messages) != 1 {
		t.Fatalf("leased %d, want 1", len(held.Messages))
	}
	// Still on disk. A relay that deleted the durable copy when it handed the
	// message out would have moved the loss window rather than closed it: the
	// collector could die and the relay could restart, and nobody would have it.
	if n := len(msgFiles(t, dir)); n != 1 {
		t.Fatalf("leasing removed the durable copy: %d files", n)
	}

	if r := ack(t, srv, "/v1/e1/st1/c2s/ack", "station-token", held.Lease); r.StatusCode != 200 {
		t.Fatalf("ack: %d", r.StatusCode)
	}
	if got := msgFiles(t, dir); len(got) != 0 {
		t.Errorf("an acknowledged message is still on disk: %v", got)
	}
}

// A relay restart releases the leases this implementation was holding, because
// they live in memory. That fails in the safe direction - the messages become
// collectable again - but an acknowledgement from before the restart must not then
// delete whatever the next collector is holding. The lease id carries a process
// epoch so that a stale acknowledgement is a 410 rather than somebody else's
// silent loss.
func TestAnAcknowledgementFromBeforeARestartIsRefused(t *testing.T) {
	dir := t.TempDir()
	srv, _ := spooled(t, dir)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("only copy"))
	stale := lease(t, srv, "/v1/e1/st1/c2s?wait=0&lease=30s", "station-token")
	if stale.Lease == "" {
		t.Fatal("no lease id")
	}

	// The restart: a new store over the same spool, and a new HTTP surface.
	restarted := NewStore()
	if _, err := restarted.OpenSpool(dir); err != nil {
		t.Fatal(err)
	}
	after := httptest.NewServer(NewServer(restarted, testAuth(), quiet()).Routes())
	t.Cleanup(after.Close)

	// The message is collectable again, which is the safe direction.
	fresh := lease(t, after, "/v1/e1/st1/c2s?wait=0&lease=30s", "station-token")
	if len(fresh.Messages) != 1 {
		t.Fatalf("the message did not come back after the restart: %d", len(fresh.Messages))
	}
	if fresh.Lease == stale.Lease {
		t.Fatalf("the new run reused the lease id %q from the old one", stale.Lease)
	}

	// And the dead collector's acknowledgement does not delete it.
	if r := ack(t, after, "/v1/e1/st1/c2s/ack", "station-token", stale.Lease); r.StatusCode != http.StatusGone {
		t.Errorf("a stale acknowledgement returned %d rather than 410", r.StatusCode)
	}
	if d := restarted.Depth("e1", "st1", "c2s"); d != 1 {
		t.Errorf("a stale acknowledgement deleted the live collector's message: depth %d", d)
	}
}

// An id survives the relay restarting, because a collector deduplicating on it
// cannot tell "the same message again" from "a new message" if the relay renames
// it in between.
func TestAMessageKeepsItsIDAcrossARestart(t *testing.T) {
	dir := t.TempDir()
	srv, _ := spooled(t, dir)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("x"))
	before := lease(t, srv, "/v1/e1/st1/c2s?wait=0&lease=30s", "station-token")

	restarted := NewStore()
	if _, err := restarted.OpenSpool(dir); err != nil {
		t.Fatal(err)
	}
	got, _ := restarted.Take("e1", "st1", "c2s", 0)
	if len(got) != 1 {
		t.Fatalf("got %d messages after the restart", len(got))
	}
	if got[0].ID != before.Messages[0].ID {
		t.Errorf("the id changed across a restart: %q then %q", before.Messages[0].ID, got[0].ID)
	}
	// And a message queued after the restart does not reuse a recovered id.
	if err := restarted.Put(Message{Estate: "e1", Station: "st1", Dir: "c2s", Body: []byte("next")}); err != nil {
		t.Fatal(err)
	}
	next, _ := restarted.Take("e1", "st1", "c2s", 0)
	if len(next) != 1 {
		t.Fatalf("got %d", len(next))
	}
	if next[0].ID == got[0].ID {
		t.Errorf("a new message reused the recovered id %q", got[0].ID)
	}
}

// Every message carries an id, leased or not, because a collector that spools
// what it has collected needs something to key on either way.
func TestEveryMessageCarriesAnIDThatDoesNotChange(t *testing.T) {
	srv, _ := newTestServer(t)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("a"))
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 2, []byte("b"))

	r := do(t, srv, "GET", "/v1/e1/st1/c2s?wait=0", "station-token", nil)
	var got []Message
	_ = json.NewDecoder(r.Body).Decode(&got)
	if len(got) != 2 {
		t.Fatalf("got %d", len(got))
	}
	if got[0].ID == "" || got[1].ID == "" {
		t.Fatalf("a message came back with no id: %+v", got)
	}
	if got[0].ID == got[1].ID {
		t.Errorf("two messages share an id: %q", got[0].ID)
	}
}
