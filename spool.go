package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The spool: the Go server's durable copy, written before the sender is told the
// message was accepted.
//
// WHY THIS EXISTS AT ALL, given that the package comment argues for memory. The
// argument was that a relay which persisted would be a relay with a backup, and
// a backup of ciphertext is a liability. That is right about LONG retention and
// wrong as "never to disk": a sender that receives a 202 and deletes its own
// copy has handed the relay the only copy, and on this transport the sender is
// often a station nobody can log into, holding the only record of an hour-long
// capture. Holding it durably for the seconds until collection is a smaller
// liability than losing it. The Worker in edge/ has always worked this way; this
// is the same guarantee for the binary a self-hoster runs.
//
// WHY IT IS OPT-IN. A container with no volume has nowhere durable to put
// anything, and writing into its own filesystem would look like durability while
// providing none. So the operator names a directory or gets today's behaviour
// unchanged, and the README says which they have.
//
// THE FORMAT IS DELIBERATELY BORING. One file per message: a single line of JSON
// naming the id, the route, the sequence number and the arrival time, then a newline,
// then the body exactly as it arrived. Splitting on the FIRST newline only, so a
// body containing newlines - or anything else - is carried byte for byte. The
// body is never decoded, re-encoded or interpreted here, for the same reason
// nothing else in this server touches it. Base64 or JSON-encoding the body would
// have cost a third of the disk for no gain.
//
// WHAT IT COSTS, stated because the cost model consumes it: one file, one fsync
// of that file and one fsync of the directory per accepted message, all inside
// the store's lock. Durability is a promise about power cuts, and a promise that
// skips the fsync is not one. See the README's Storage section for the measured
// bytes per message.
type spool struct {
	dir string
	// next file number. Fixed width and zero padded, so the order files sort in
	// is the order they were written in, and a restart keeps counting from the
	// highest it found rather than overwriting it.
	next uint64
}

const (
	spoolExt     = ".msg"
	spoolTmpPre  = "writing-"
	spoolCorrupt = ".corrupt"
)

// SpoolReport is what a restart recovered, for the operator to read at startup.
//
// A relay that silently recovered nothing looks exactly like one that silently
// recovered everything, and the difference is whether somebody's capture still
// exists.
type SpoolReport struct {
	Dir      string
	Messages int
	Bytes    int64 // of message bodies, not of files
	// Files that did not parse as messages. Moved aside rather than deleted, and
	// named here, because the bytes may be the only remaining copy of something.
	Quarantined []string
}

// spoolHead is the first line of a spool file.
//
// At is unix nanoseconds rather than a formatted time: it round-trips exactly,
// sorts, and has no timezone to get wrong. It is the relay's own clock and is
// used for expiry only, as everywhere else in this package.
type spoolHead struct {
	// ID is written because it has to survive the restart too. A collector
	// deduplicates on it, and a message that came back with a new id after a
	// relay restart would be indistinguishable from a second message.
	ID      string `json:"id"`
	Estate  string `json:"estate"`
	Station string `json:"station"`
	Dir     string `json:"dir"`
	Seq     uint64 `json:"seq"`
	At      int64  `json:"at"`
}

// OpenSpool makes the store durable, and loads whatever a previous run left.
//
// Called once at startup, before the server accepts anything. It creates the
// directory if it is missing, and returns an error rather than starting
// non-durable if it cannot: an operator who asked for durability and did not get
// it must be told at the point of asking, not discover it after a restart lost a
// message.
func (s *Store) OpenSpool(dir string) (SpoolReport, error) {
	report := SpoolReport{Dir: dir}
	if strings.TrimSpace(dir) == "" {
		return report, errors.New("a spool needs a directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return report, fmt.Errorf("spool directory %s: %w", dir, err)
	}
	sp := &spool{dir: dir}
	msgs, quarantined, highest, err := sp.load()
	if err != nil {
		return report, err
	}
	sp.next = highest + 1

	s.mu.Lock()
	defer s.mu.Unlock()
	s.spool = sp
	for _, m := range msgs {
		k := key(m.Estate, m.Station, m.Dir)
		s.q[k] = append(s.q[k], m)
		report.Bytes += int64(len(m.Body))
		// Keep counting ids from the highest one recovered. Reusing an id would
		// make two different messages look like one redelivery to a collector
		// deduplicating on it, and the second would be dropped as a duplicate.
		if n, ok := messageNumber(m.ID); ok && n > s.ids {
			s.ids = n
		}
	}
	report.Messages = len(msgs)
	report.Quarantined = quarantined
	return report, nil
}

// messageNumber reads the counter back out of an id, which is the one place the
// id's shape is relied on. Kept next to the thing that writes it.
func messageNumber(id string) (uint64, bool) {
	n, err := strconv.ParseUint(strings.TrimPrefix(id, "m"), 10, 64)
	if err != nil || !strings.HasPrefix(id, "m") {
		return 0, false
	}
	return n, true
}

// load reads every message left on disk, in the order they were written.
func (sp *spool) load() (msgs []Message, quarantined []string, highest uint64, err error) {
	entries, err := os.ReadDir(sp.dir)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("reading spool %s: %w", sp.dir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		switch {
		case strings.HasPrefix(name, spoolTmpPre):
			// A write that did not finish. It was never acknowledged to a
			// sender, so nothing is lost by removing it, and leaving it would
			// mean a crash loop filled the disk with fragments.
			_ = os.Remove(filepath.Join(sp.dir, name))
		case strings.HasSuffix(name, spoolExt):
			names = append(names, name)
		default:
			// Not a message and never was. Anything else in this directory
			// belongs to whoever put it there.
		}
	}
	sort.Strings(names) // fixed-width numbers, so this is write order

	for _, name := range names {
		full := filepath.Join(sp.dir, name)
		m, err := readSpoolFile(full)
		if err != nil {
			// Neither answer here is free. Refusing to start would make one
			// unreadable file an outage for every station on this relay;
			// deleting it silently is the thing this server refuses to do
			// everywhere else. So it is moved aside and named.
			aside := full + spoolCorrupt
			if renameErr := os.Rename(full, aside); renameErr == nil {
				quarantined = append(quarantined, aside)
			} else {
				quarantined = append(quarantined, full)
			}
			continue
		}
		if n, ok := spoolNumber(name); ok && n > highest {
			highest = n
		}
		msgs = append(msgs, m)
	}
	return msgs, quarantined, highest, nil
}

func spoolNumber(name string) (uint64, bool) {
	var n uint64
	trimmed := strings.TrimSuffix(name, spoolExt)
	if trimmed == name {
		return 0, false
	}
	if _, err := fmt.Sscanf(trimmed, "%d", &n); err != nil {
		return 0, false
	}
	return n, true
}

func readSpoolFile(path string) (Message, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Message{}, err
	}
	// The first newline, and only the first: everything after it is the body,
	// whatever it contains.
	i := bytes.IndexByte(raw, '\n')
	if i < 0 {
		return Message{}, fmt.Errorf("%s has no header", path)
	}
	var head spoolHead
	if err := json.Unmarshal(raw[:i], &head); err != nil {
		return Message{}, fmt.Errorf("%s: %w", path, err)
	}
	if !validRoute(head.Estate, head.Station, head.Dir) {
		return Message{}, fmt.Errorf("%s names no valid route", path)
	}
	return Message{
		ID:      head.ID,
		Estate:  head.Estate,
		Station: head.Station,
		Dir:     head.Dir,
		Seq:     head.Seq,
		Body:    raw[i+1:],
		At:      time.Unix(0, head.At),
		file:    path,
	}, nil
}

// write puts the message on disk durably, and returns the file holding it.
//
// Temporary name, fsync, rename, fsync the directory. Each step is there for a
// specific failure: without the temporary name a crash leaves a half-written
// file under a name the loader will read; without the file fsync the rename can
// land before the contents; without the directory fsync the rename itself can be
// lost. A "durable" write missing any of them is a claim rather than a
// guarantee, and this package has had enough of those.
func (sp *spool) write(m Message) (string, error) {
	head, err := json.Marshal(spoolHead{
		ID: m.ID, Estate: m.Estate, Station: m.Station, Dir: m.Dir,
		Seq: m.Seq, At: m.At.UnixNano(),
	})
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(sp.dir, spoolTmpPre+"*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	fail := func(err error) (string, error) {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", err
	}
	if _, err := tmp.Write(append(head, '\n')); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(m.Body); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", err
	}
	final := filepath.Join(sp.dir, fmt.Sprintf("%020d%s", sp.next, spoolExt))
	if err := os.Rename(tmpName, final); err != nil {
		_ = os.Remove(tmpName)
		return "", err
	}
	sp.next++
	if err := syncDir(sp.dir); err != nil {
		// The bytes are in the file and the name is in place, so only the
		// durability of the directory entry is in doubt. The sender must not be
		// told "accepted" on a maybe, and the file is removed rather than left
		// for a restart to find, so that what is on disk and what is in the
		// queue cannot disagree.
		_ = os.Remove(final)
		return "", err
	}
	return final, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// remove drops the durable copy. Called when a message is collected or expires,
// because "held only until collected, or seven days" has to be true of the disk
// as well as of the queue.
func (sp *spool) remove(msgs ...Message) {
	for _, m := range msgs {
		if m.file == "" {
			continue
		}
		if err := os.Remove(m.file); err != nil && !errors.Is(err, os.ErrNotExist) {
			// Nothing useful to do here and nowhere to report it from: the
			// message has been handed to its recipient either way. A file left
			// behind is read again on the next restart and delivered twice,
			// which is why collection is idempotent at the collector.
			continue
		}
	}
}
