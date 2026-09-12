package relay

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The storage model, asserted here because conformance/ has no way to see it.
//
// conformance/ is asserted over HTTP against a base URL. A storage model is not
// observable to a client: a relay that holds a message in memory and a relay
// that writes it to disk answer every request in the suite identically. That is
// how the two implementations came to disagree behind one README sentence while
// both passed - heliograph-io/heliograph-cloud#47.
//
// So each implementation asserts its own storage model in its own tests. This
// file is the Go half. edge/test/storage-model.test.ts is the Worker half, and
// it reads Durable Object storage directly for the same reason.

// The claim this guards is the Storage table in README.md: the Go binary holds
// messages "in memory".
//
// What would make it fail: a spool file next to the binary, or a temporary file
// holding a body, added by anybody making this durable without also correcting
// the README. What it does NOT cover: a write to an absolute path elsewhere,
// which is why the README names in-memory as the mechanism rather than
// promising more than this proves.
func TestTheGoRelayWritesNothingToDiskWhereItRuns(t *testing.T) {
	work, tmp := t.TempDir(), t.TempDir()
	t.Chdir(work)
	t.Setenv("TMPDIR", tmp)

	srv, _ := newTestServer(t)
	// Big enough that anything spooling it would have to put it somewhere, and
	// recognisable if it lands in a file.
	body := bytes.Repeat([]byte{0xAB}, 512<<10)
	if r := put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, body); r.StatusCode != 202 {
		t.Fatalf("put: %d", r.StatusCode)
	}

	for _, dir := range []string{work, tmp} {
		var found []string
		err := filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p != dir {
				found = append(found, p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(found) > 0 {
			t.Errorf("the relay wrote to disk in %s: %v", dir, found)
		}
	}
}

// The other half of the same claim, and the half a self-hoster feels: the
// README says a restart of the Go binary "drops undelivered messages, which
// costs a re-run".
//
// A restart is a new process with a new Store and the same configuration, which
// is what this builds. What would make it fail: a Store that reads a spool at
// construction, added without correcting the table that says it does not.
func TestARestartOfTheGoRelayDropsWhatWasNotCollected(t *testing.T) {
	srv, st := newTestServer(t)
	if r := put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("only copy")); r.StatusCode != 202 {
		t.Fatalf("put: %d", r.StatusCode)
	}
	if d := st.Depth("e1", "st1", "c2s"); d != 1 {
		t.Fatalf("the message was not queued at all: depth %d", d)
	}

	restarted := NewStore()
	if d := restarted.Depth("e1", "st1", "c2s"); d != 0 {
		t.Errorf("a fresh Store found %d message(s) the old one held, so this build is durable and the README's Storage table is now wrong", d)
	}
}
