package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testAuth() *StaticAuth {
	a := NewStaticAuth()
	a.SetControl("e1", "control-token")
	a.SetStation("e1", "station-token")
	a.SetControl("e2", "other-control")
	a.SetStation("e2", "other-station")
	return a
}

func newTestServer(t *testing.T) (*httptest.Server, *Store) {
	t.Helper()
	st := NewStore()
	srv := httptest.NewServer(NewServer(st, testAuth(), quiet()).Routes())
	t.Cleanup(srv.Close)
	return srv, st
}

func do(t *testing.T, srv *httptest.Server, method, path, tok string, body []byte) *http.Response {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func put(t *testing.T, srv *httptest.Server, path, tok string, seq uint64, body []byte) *http.Response {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"seq": seq, "body": body})
	return do(t, srv, "POST", path, tok, b)
}

func TestAMessageGoesInAndComesBackUnchanged(t *testing.T) {
	srv, _ := newTestServer(t)
	want := []byte{0x00, 0xff, 0x10, 'c', 'i', 'p', 'h', 'e', 'r'}

	if r := put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, want); r.StatusCode != 202 {
		t.Fatalf("put: %d", r.StatusCode)
	}
	r := do(t, srv, "GET", "/v1/e1/st1/c2s?wait=0", "station-token", nil)
	var got []Message
	if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d messages", len(got))
	}
	// Byte for byte. The relay must not normalise, re-encode or touch it.
	if !bytes.Equal(got[0].Body, want) {
		t.Errorf("the body changed in transit: %v", got[0].Body)
	}
	if got[0].Seq != 1 {
		t.Errorf("seq changed: %d", got[0].Seq)
	}
}

// The requirement that makes the whole product safe: a station credential must
// not be able to queue a request. It sits on a machine nobody can reach and
// cannot be rotated quickly.
func TestAStationTokenCannotQueueARequest(t *testing.T) {
	srv, _ := newTestServer(t)
	r := put(t, srv, "/v1/e1/st1/c2s", "station-token", 1, []byte("evil"))
	if r.StatusCode == 202 {
		t.Fatal("a station token queued a request")
	}
	if r.StatusCode != 401 {
		t.Errorf("expected 401, got %d", r.StatusCode)
	}
}

func TestAControlTokenCannotPublishAStatus(t *testing.T) {
	srv, _ := newTestServer(t)
	if r := put(t, srv, "/v1/e1/st1/s2c", "control-token", 1, []byte("fake log")); r.StatusCode == 202 {
		t.Fatal("a control token published a status as the station")
	}
}

// One estate's credential must be useless against another's, or the relay is a
// single tenant pretending to be many.
func TestOneEstateCannotReachAnother(t *testing.T) {
	srv, _ := newTestServer(t)
	if r := put(t, srv, "/v1/e2/st1/c2s", "control-token", 1, []byte("x")); r.StatusCode == 202 {
		t.Fatal("e1's control token wrote into e2")
	}
	put(t, srv, "/v1/e2/st1/c2s", "other-control", 1, []byte("x"))
	r := do(t, srv, "GET", "/v1/e2/st1/c2s?wait=0", "station-token", nil)
	if r.StatusCode != 401 {
		t.Errorf("e1's station token read e2's queue: %d", r.StatusCode)
	}
}

func TestNoTokenIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	if r := put(t, srv, "/v1/e1/st1/c2s", "", 1, []byte("x")); r.StatusCode != 401 {
		t.Errorf("put with no token: %d", r.StatusCode)
	}
	if r := do(t, srv, "GET", "/v1/e1/st1/c2s?wait=0", "", nil); r.StatusCode != 401 {
		t.Errorf("get with no token: %d", r.StatusCode)
	}
}

func TestAnUnknownEstateIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	// No tokens are configured for e9, so `match` must refuse rather than
	// treating the zero value as a match. That would authorise everybody.
	if r := put(t, srv, "/v1/e9/st1/c2s", "control-token", 1, []byte("x")); r.StatusCode == 202 {
		t.Fatal("wrote to an estate with no configured tokens")
	}
	if r := put(t, srv, "/v1/e9/st1/c2s", "", 1, []byte("x")); r.StatusCode == 202 {
		t.Fatal("an empty token matched an unconfigured estate")
	}
}

func TestCollectingRemovesTheMessage(t *testing.T) {
	srv, _ := newTestServer(t)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("once"))
	do(t, srv, "GET", "/v1/e1/st1/c2s?wait=0", "station-token", nil)

	r := do(t, srv, "GET", "/v1/e1/st1/c2s?wait=0", "station-token", nil)
	var got []Message
	_ = json.NewDecoder(r.Body).Decode(&got)
	if len(got) != 0 {
		t.Errorf("the message was delivered twice: %d", len(got))
	}
}

// A long poll must return as soon as something arrives, or an idle loop is
// either expensive or slow and there is no third option.
func TestALongPollWakesOnDelivery(t *testing.T) {
	srv, _ := newTestServer(t)
	done := make(chan int, 1)
	go func() {
		r := do(t, srv, "GET", "/v1/e1/st1/c2s", "station-token", nil)
		var got []Message
		_ = json.NewDecoder(r.Body).Decode(&got)
		done <- len(got)
	}()
	time.Sleep(150 * time.Millisecond) // let the poll get in and wait
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("wake up"))

	select {
	case n := <-done:
		if n != 1 {
			t.Errorf("the poll woke with %d messages", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the long poll did not wake when a message arrived")
	}
}

// A full queue means the recipient has stopped collecting. Refusing the newest
// rather than dropping the oldest is what keeps the gap visible to the sender,
// which is the side that can do something about it.
func TestAFullQueueRefusesRatherThanDiscarding(t *testing.T) {
	st := NewStore()
	st.max = 2
	srv := httptest.NewServer(NewServer(st, testAuth(), quiet()).Routes())
	t.Cleanup(srv.Close)

	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("first"))
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 2, []byte("second"))
	r := put(t, srv, "/v1/e1/st1/c2s", "control-token", 3, []byte("third"))
	if r.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", r.StatusCode)
	}

	// And the earlier ones are still there. Silently dropping one would leave
	// the recipient a gap it reads as a delivered sequence.
	got, _ := st.Take("e1", "st1", "c2s", 0)
	if len(got) != 2 || !bytes.Equal(got[0].Body, []byte("first")) {
		t.Errorf("the oldest message was discarded: %d left", len(got))
	}
}

func TestAnOversizedMessageIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	r := put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, make([]byte, MaxBodyBytes+1))
	if r.StatusCode != http.StatusRequestEntityTooLarge && r.StatusCode != http.StatusBadRequest {
		t.Errorf("expected a refusal, got %d", r.StatusCode)
	}
}

func TestAnInvalidDirectionIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	if r := put(t, srv, "/v1/e1/st1/sideways", "control-token", 1, []byte("x")); r.StatusCode == 202 {
		t.Error("accepted a direction that is not c2s or s2c")
	}
}

func TestExpiredMessagesAreDropped(t *testing.T) {
	st := NewStore()
	now := time.Now()
	st.now = func() time.Time { return now }
	if err := st.Put(Message{Estate: "e", Station: "s", Dir: "c2s", Body: []byte("old")}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(DefaultTTL + time.Hour)
	if d := st.Depth("e", "s", "c2s"); d != 0 {
		t.Errorf("an expired message was still queued: %d", d)
	}
	if n := st.Sweep(); n != 0 {
		t.Errorf("Sweep found %d after Depth had already expired them", n)
	}
}

func TestHealthNeedsNoToken(t *testing.T) {
	srv, _ := newTestServer(t)
	if r := do(t, srv, "GET", "/health", "", nil); r.StatusCode != 200 {
		t.Errorf("health: %d", r.StatusCode)
	}
}

// The relay stores what it is given and interprets none of it. If it ever
// started rejecting bodies for their shape, it would be reading them.
func TestTheBodyIsNeverInterpreted(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, body := range [][]byte{
		{}, {0}, []byte("{not json"), bytes.Repeat([]byte{0xff}, 1024),
	} {
		if r := put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, body); r.StatusCode != 202 {
			t.Errorf("refused a %d-byte body: %d", len(body), r.StatusCode)
		}
	}
}

// Seq is stored and returned but never enforced here. Ordering is the
// recipient's job, where the number is signed and a hostile relay cannot lie
// about it. Enforcing it here would look like a safety feature and be worth
// nothing.
func TestSeqIsCarriedButNotEnforced(t *testing.T) {
	srv, st := newTestServer(t)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 99, []byte("a"))
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("b"))
	got, _ := st.Take("e1", "st1", "c2s", 0)
	if len(got) != 2 {
		t.Fatalf("got %d", len(got))
	}
	if got[0].Seq != 99 || got[1].Seq != 1 {
		t.Errorf("the relay reordered or rewrote seq: %d then %d", got[0].Seq, got[1].Seq)
	}
}
