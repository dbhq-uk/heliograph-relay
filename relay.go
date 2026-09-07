// Package relay stores and forwards opaque messages between a control and a
// station, and can read none of them.
//
// THERE IS NO CRYPTOGRAPHY IN THIS PACKAGE, and that is the design rather than
// an omission. Every message arrives already sealed by the client, bound to its
// estate, its station, its direction and its sequence number, and signed. This
// server sees a byte slice, a routing key and a length.
//
// That is what makes the security claim checkable: there is no key here to
// leak, no plaintext to subpoena, and no code path that could be persuaded to
// produce either. A reviewer can establish it by reading one small file rather
// than by trusting an operator.
//
// What it can do, and the docs say so plainly: see who is talking to whom, how
// often, and how big the messages are. It can also refuse to deliver. It cannot
// read, alter, forge or reorder without the far side noticing.
package relay

import (
	"errors"
	"sync"
	"time"
)

// Message is one sealed blob, plus the routing the server needs to move it.
//
// Seq is stored but NOT interpreted. Ordering is enforced by the recipient,
// where the number is signed and a hostile relay cannot lie about it. Enforcing
// it here would look like a safety feature and would be worth nothing.
type Message struct {
	Estate  string    `json:"estate"`
	Station string    `json:"station"`
	Dir     string    `json:"dir"` // c2s or s2c
	Seq     uint64    `json:"seq"`
	Body    []byte    `json:"body"` // ciphertext. Opaque here, always
	At      time.Time `json:"at"`   // the server's own clock, for expiry only
}

// Store holds undelivered messages.
//
// In memory, because that is the honest shape for something that deletes on
// acknowledgement and expires in days. A relay that persisted to disk would be
// a relay with a backup, and a backup of ciphertext is a liability that has to
// be explained to every customer who asks what happens to their data.
type Store struct {
	mu  sync.Mutex
	q   map[string][]Message // keyed by estate/station/dir
	ttl time.Duration
	max int // per queue, so one estate cannot exhaust the server
	now func() time.Time
}

// Limits chosen so that a misbehaving client is a problem for itself.
const (
	DefaultTTL      = 7 * 24 * time.Hour
	DefaultMaxQueue = 256
	MaxBodyBytes    = 8 << 20 // 8 MiB: a captured log, comfortably
)

var (
	ErrTooLarge  = errors.New("message is larger than the relay will carry")
	ErrQueueFull = errors.New("this queue is full: the recipient is not collecting")
	ErrBadRoute  = errors.New("a message must name an estate, a station and a direction")
)

func NewStore() *Store {
	return &Store{
		q:   map[string][]Message{},
		ttl: DefaultTTL,
		max: DefaultMaxQueue,
		now: time.Now,
	}
}

func key(estate, station, dir string) string {
	return estate + "/" + station + "/" + dir
}

func validRoute(estate, station, dir string) bool {
	if estate == "" || station == "" {
		return false
	}
	return dir == "c2s" || dir == "s2c"
}

// Put accepts a message for later collection.
func (s *Store) Put(m Message) error {
	if !validRoute(m.Estate, m.Station, m.Dir) {
		return ErrBadRoute
	}
	if len(m.Body) > MaxBodyBytes {
		return ErrTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(m.Estate, m.Station, m.Dir)
	s.expireLocked(k)

	// A full queue means the recipient has stopped collecting. Refusing the
	// NEWEST rather than dropping the oldest is deliberate: silently discarding
	// an earlier message would leave a gap the recipient reads as a delivered
	// sequence, and it would never know. A refusal reaches the sender, which is
	// the side that can do something about it.
	if len(s.q[k]) >= s.max {
		return ErrQueueFull
	}
	m.At = s.now()
	s.q[k] = append(s.q[k], m)
	return nil
}

// Take returns everything queued for a recipient and removes it.
//
// Delete on collection, not on a separate acknowledgement. A second round trip
// to confirm receipt would mean holding ciphertext for longer in exchange for
// surviving a client that crashes between reading and processing - and that
// client can simply ask for the step again, which is a cost heliograph already
// accepts everywhere else.
func (s *Store) Take(estate, station, dir string, limit int) ([]Message, error) {
	if !validRoute(estate, station, dir) {
		return nil, ErrBadRoute
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(estate, station, dir)
	s.expireLocked(k)

	msgs := s.q[k]
	if len(msgs) == 0 {
		return nil, nil
	}
	if limit > 0 && len(msgs) > limit {
		s.q[k] = msgs[limit:]
		return msgs[:limit], nil
	}
	delete(s.q, k)
	return msgs, nil
}

// Depth is how many messages are waiting, for the operator's own metrics.
func (s *Store) Depth(estate, station, dir string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(estate, station, dir)
	s.expireLocked(k)
	return len(s.q[k])
}

func (s *Store) expireLocked(k string) {
	msgs := s.q[k]
	if len(msgs) == 0 {
		return
	}
	cut := s.now().Add(-s.ttl)
	i := 0
	for i < len(msgs) && msgs[i].At.Before(cut) {
		i++
	}
	if i == len(msgs) {
		delete(s.q, k)
		return
	}
	if i > 0 {
		s.q[k] = msgs[i:]
	}
}

// Sweep drops everything expired, across every queue.
func (s *Store) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := 0
	for k := range s.q {
		before += len(s.q[k])
	}
	for k := range s.q {
		s.expireLocked(k)
	}
	after := 0
	for k := range s.q {
		after += len(s.q[k])
	}
	return before - after
}
