package relay

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The durable half of the Go server, which until now did not exist.
//
// A sender that receives a 202 and deletes its own copy has handed the relay the
// only copy, and on this transport the sender is often a station nobody can log
// into. The Worker has always persisted before acknowledging; this is the same
// guarantee for the binary a self-hoster runs, and it is opt-in because a
// container with no volume has nowhere durable to put it.
//
// heliograph-io/heliograph-cloud#8.

// spooled builds a server whose store is durable, and returns both so a test can
// restart the store underneath the same directory.
func spooled(t *testing.T, dir string) (*httptest.Server, *Store) {
	t.Helper()
	st := NewStore()
	if _, err := st.OpenSpool(dir); err != nil {
		t.Fatalf("OpenSpool(%q): %v", dir, err)
	}
	srv := httptest.NewServer(NewServer(st, testAuth(), quiet()).Routes())
	t.Cleanup(srv.Close)
	return srv, st
}

func msgFiles(t *testing.T, dir string) []string {
	t.Helper()
	got, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// The assertion the whole issue is about: a 202 means the message is still there
// after the process that accepted it has gone.
func TestASpooledMessageSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	// Bytes that are not valid UTF-8, not valid JSON, and contain the newline
	// the on-disk format uses as its own delimiter. If the spool ever starts
	// interpreting a body, this is what catches it.
	want := []byte{0x00, 0xff, '\n', 0x7b, '"', '\n', 'c', 'i', 'p', 'h', 'e', 'r', 0xfe}

	srv, _ := spooled(t, dir)
	if r := put(t, srv, "/v1/e1/st1/c2s", "control-token", 42, want); r.StatusCode != 202 {
		t.Fatalf("put: %d", r.StatusCode)
	}

	// What a restart is: a new process, a new Store, the same directory.
	restarted := NewStore()
	report, err := restarted.OpenSpool(dir)
	if err != nil {
		t.Fatalf("OpenSpool after restart: %v", err)
	}
	if report.Messages != 1 {
		t.Errorf("the report says %d messages, want 1", report.Messages)
	}
	got, err := restarted.Take("e1", "st1", "c2s", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("a restart lost the message: %d came back", len(got))
	}
	if !bytes.Equal(got[0].Body, want) {
		t.Errorf("the body changed on the way through the spool: %v", got[0].Body)
	}
	if got[0].Seq != 42 {
		t.Errorf("seq changed: %d", got[0].Seq)
	}
	if got[0].Estate != "e1" || got[0].Station != "st1" || got[0].Dir != "c2s" {
		t.Errorf("the route changed: %+v", got[0])
	}
}

// "Deleted on collection" has to stay true of the disk as well as the queue, or
// durability has quietly turned into a backup of ciphertext.
func TestCollectingRemovesTheSpooledCopy(t *testing.T) {
	dir := t.TempDir()
	srv, _ := spooled(t, dir)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("once"))
	if n := len(msgFiles(t, dir)); n != 1 {
		t.Fatalf("the message was not spooled at all: %d files", n)
	}

	do(t, srv, "GET", "/v1/e1/st1/c2s?wait=0", "station-token", nil)

	if got := msgFiles(t, dir); len(got) != 0 {
		t.Errorf("collecting left the message on disk: %v", got)
	}
	restarted := NewStore()
	if _, err := restarted.OpenSpool(dir); err != nil {
		t.Fatal(err)
	}
	if d := restarted.Depth("e1", "st1", "c2s"); d != 0 {
		t.Errorf("a restart found %d collected message(s) again", d)
	}
}

// A limit collects part of a queue. The part left behind must still be durable,
// or a client reading in batches loses everything it has not asked for yet.
func TestTakingPartOfAQueueLeavesTheRestSpooled(t *testing.T) {
	dir := t.TempDir()
	srv, _ := spooled(t, dir)
	for _, seq := range []uint64{1, 2, 3} {
		put(t, srv, "/v1/e1/st1/c2s", "control-token", seq, []byte{byte(seq)})
	}

	do(t, srv, "GET", "/v1/e1/st1/c2s?wait=0&limit=1", "station-token", nil)

	if n := len(msgFiles(t, dir)); n != 2 {
		t.Errorf("expected 2 messages still spooled, found %d", n)
	}
	restarted := NewStore()
	if _, err := restarted.OpenSpool(dir); err != nil {
		t.Fatal(err)
	}
	got, _ := restarted.Take("e1", "st1", "c2s", 0)
	if len(got) != 2 || got[0].Seq != 2 || got[1].Seq != 3 {
		t.Errorf("the remainder came back wrong after a restart: %+v", got)
	}
}

// If the message cannot be made durable, the sender must not be told it was
// accepted. That is the whole point: the 202 is the promise.
func TestAPutIsRefusedWhenItCannotBeMadeDurable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	srv, st := spooled(t, dir)

	// Replace the directory with a regular file, so a write inside it fails for
	// any user including root. Permissions would not do: a test running as root
	// ignores them, and this assertion has to hold in a container too.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("only copy"))
	if r.StatusCode == 202 {
		t.Fatal("the relay accepted a message it could not make durable")
	}
	// 503 rather than 500, for the same reason a full queue is a 429: a full
	// disk or a read-only volume is a condition to retry, not a fault to go
	// looking for on this side.
	if r.StatusCode != 503 {
		t.Errorf("expected 503, got %d", r.StatusCode)
	}
	if d := st.Depth("e1", "st1", "c2s"); d != 0 {
		t.Errorf("the message was queued anyway: depth %d", d)
	}
}

// A write interrupted by a crash must not come back as a message. The spool
// writes to a temporary name and renames, so a half-written file never has a
// name the loader will read - and the leftovers are cleared rather than left to
// accumulate.
func TestAnUnfinishedWriteIsNotLoadedAsAMessage(t *testing.T) {
	dir := t.TempDir()
	srv, _ := spooled(t, dir)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("finished"))

	half := filepath.Join(dir, "writing-1234567")
	if err := os.WriteFile(half, []byte(`{"estate":"e1","stati`), 0o600); err != nil {
		t.Fatal(err)
	}

	restarted := NewStore()
	report, err := restarted.OpenSpool(dir)
	if err != nil {
		t.Fatalf("a leftover temporary file stopped the relay starting: %v", err)
	}
	if report.Messages != 1 {
		t.Errorf("loaded %d messages, want the one that finished", report.Messages)
	}
	if len(report.Quarantined) != 0 {
		t.Errorf("an unfinished write was quarantined rather than discarded: %v", report.Quarantined)
	}
	if _, err := os.Stat(half); !os.IsNotExist(err) {
		t.Errorf("the leftover temporary file is still there: %v", err)
	}
}

// A message file that does not parse is a real anomaly, and neither answer to it
// is free: refusing to start makes one bad file an outage for every station on
// that relay, and dropping it silently is the thing this server refuses to do
// everywhere else. So it is moved aside, named in the report, and the relay
// starts.
func TestACorruptSpoolFileIsMovedAsideRatherThanLosingTheRelay(t *testing.T) {
	dir := t.TempDir()
	srv, _ := spooled(t, dir)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("fine"))

	bad := filepath.Join(dir, "00000000000000009999.msg")
	if err := os.WriteFile(bad, []byte("this was never a message\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	restarted := NewStore()
	report, err := restarted.OpenSpool(dir)
	if err != nil {
		t.Fatalf("one unreadable file stopped the relay starting: %v", err)
	}
	if report.Messages != 1 {
		t.Errorf("loaded %d messages, want 1", report.Messages)
	}
	if len(report.Quarantined) != 1 || !strings.HasSuffix(report.Quarantined[0], ".corrupt") {
		t.Errorf("the unreadable file was not named as quarantined: %v", report.Quarantined)
	}
	// The bytes stay on disk for whoever has to explain them.
	if _, err := os.Stat(bad + ".corrupt"); err != nil {
		t.Errorf("the unreadable file was deleted rather than moved aside: %v", err)
	}
	// And it is not read again on the next start.
	again := NewStore()
	report2, err := again.OpenSpool(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(report2.Quarantined) != 0 {
		t.Errorf("a file already moved aside was quarantined again: %v", report2.Quarantined)
	}
}

// Expiry deletes the copy on disk too. Seven days is a ceiling on retention, and
// a ceiling that only applies to memory is not one.
func TestAnExpiredSpooledMessageLeavesNoFile(t *testing.T) {
	dir := t.TempDir()
	st := NewStore()
	if _, err := st.OpenSpool(dir); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	st.now = func() time.Time { return now }
	if err := st.Put(Message{Estate: "e1", Station: "st1", Dir: "c2s", Body: []byte("old")}); err != nil {
		t.Fatal(err)
	}

	now = now.Add(DefaultTTL + time.Hour)
	if n := st.Sweep(); n != 1 {
		t.Errorf("Sweep expired %d, want 1", n)
	}
	if got := msgFiles(t, dir); len(got) != 0 {
		t.Errorf("an expired message is still on disk: %v", got)
	}
}

// Which guarantee a deployment gives, answered by the deployment rather than by
// its documentation.
//
// This is the lesson of heliograph-io/heliograph-cloud#47 in one endpoint. The
// README said "never written to disk" of a relay that wrote everything to disk,
// and nobody could tell by asking. /health now says, without a token, for the
// same reason /version does: a claim you need a credential to check is a claim
// people take on trust.
func TestHealthSaysWhetherThisDeploymentIsDurable(t *testing.T) {
	var health struct {
		OK      bool `json:"ok"`
		Durable bool `json:"durable"`
	}

	plain, _ := newTestServer(t)
	r := do(t, plain, "GET", "/health", "", nil)
	if err := json.NewDecoder(r.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if !health.OK {
		t.Error("health stopped saying ok")
	}
	if health.Durable {
		t.Error("a relay with no spool reported itself durable")
	}

	durable, _ := spooled(t, t.TempDir())
	r = do(t, durable, "GET", "/health", "", nil)
	if err := json.NewDecoder(r.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if !health.Durable {
		t.Error("a relay with a spool reported itself not durable")
	}
}

// What a retained message costs on disk, measured rather than assumed, because
// the cost model consumes it (heliograph-io/heliograph-cloud#12).
//
// The guard that matters here is the multiplier. A spool that base64-encoded the
// body, or wrote JSON around it, would cost a third more disk for nothing, and
// the only way anybody would find out is a full volume.
func TestASpooledMessageCostsTheBodyPlusASmallHeader(t *testing.T) {
	for _, raw := range []int{1 << 10, 64 << 10, 1 << 20} {
		dir := t.TempDir()
		srv, _ := spooled(t, dir)
		put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, bytes.Repeat([]byte{0xAB}, raw))

		files := msgFiles(t, dir)
		if len(files) != 1 {
			t.Fatalf("%d bytes: %d files", raw, len(files))
		}
		info, err := os.Stat(files[0])
		if err != nil {
			t.Fatal(err)
		}
		overhead := info.Size() - int64(raw)
		t.Logf("retained: raw %d B, on disk %d B, header and delimiter %d B (%.3fx the body)",
			raw, info.Size(), overhead, float64(info.Size())/float64(raw))
		if overhead < 0 {
			t.Errorf("%d bytes: the body was truncated on disk", raw)
		}
		// The header is one line of JSON naming the route, the sequence number
		// and the time. A route name can be long, but not this long: anything
		// over this is the body being encoded rather than written.
		if overhead > 512 {
			t.Errorf("%d bytes: %d bytes of overhead, so the body is not being written as it arrived", raw, overhead)
		}
	}
}

// The report is what the operator sees at startup, and a restart that quietly
// recovers nothing is indistinguishable from one that recovers everything unless
// it says.
func TestTheReportCountsWhatWasRecovered(t *testing.T) {
	dir := t.TempDir()
	srv, _ := spooled(t, dir)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, bytes.Repeat([]byte{0xAB}, 1000))
	put(t, srv, "/v1/e1/st2/s2c", "station-token", 2, bytes.Repeat([]byte{0xCD}, 2000))

	restarted := NewStore()
	report, err := restarted.OpenSpool(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Messages != 2 {
		t.Errorf("messages recovered: %d, want 2", report.Messages)
	}
	if report.Bytes < 3000 {
		t.Errorf("bytes recovered: %d, want at least the 3000 of body", report.Bytes)
	}
	if report.Dir != dir {
		t.Errorf("the report names %q rather than the spool it read", report.Dir)
	}
}
