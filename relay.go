// Package relay stores and forwards opaque messages between a control and a
// station, and can read none of them.
//
// THERE IS NO KEY HERE WORTH STEALING AND NO PLAINTEXT TO SUBPOENA, and that is
// the design rather than an omission. Every message arrives already sealed by
// the client, bound to its estate, its station, its direction and its sequence
// number, and signed. This server sees a byte slice, a routing key and a length.
//
// THIS COMMENT USED TO SAY "THERE IS NO CRYPTOGRAPHY IN THIS PACKAGE", and it
// is corrected here rather than quietly edited, because it was offered as a
// reason to trust this component. That sentence was a PROXY for the claim above,
// and the proxy has narrowed while the claim has not: verify.go verifies
// authorisation lease signatures with crypto/ed25519, and a public key is not a
// secret. An attacker who takes everything this relay holds gets a key that
// checks signatures and makes none.
//
// The narrowing is held in place by the linker rather than by this paragraph.
// TestTheRelayBinaryCannotSignALease reads the built binary's symbol table and
// fails if any route to constructing an ed25519 private key is reachable from
// main, so "this relay cannot mint its own authority" is a measurement.
// heliograph-io/heliograph-cloud#75 has the decision and the options it beat.
//
// What still makes the security claim checkable: there is no private key here
// to leak, no plaintext to subpoena, and no code path that could be persuaded to
// produce either. A reviewer can establish it by reading one small file rather
// than by trusting an operator.
//
// What it can do, and the docs say so plainly: see who is talking to whom, how
// often, and how big the messages are. It can also refuse to deliver. It cannot
// read, alter, forge or reorder without the far side noticing.
package relay

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// Message is one sealed blob, plus the routing the server needs to move it.
//
// Seq is stored but NOT interpreted. Ordering is enforced by the recipient,
// where the number is signed and a hostile relay cannot lie about it. Enforcing
// it here would look like a safety feature and would be worth nothing.
type Message struct {
	// ID is stable for the life of the message, including across a redelivery.
	// It is what a collector deduplicates on: an expired lease followed by a
	// successful one delivers the same message twice, and the collector has to
	// be able to tell. Unique within its route, opaque, and not comparable
	// between routes.
	ID      string    `json:"id"`
	Estate  string    `json:"estate"`
	Station string    `json:"station"`
	Dir     string    `json:"dir"` // c2s or s2c
	Seq     uint64    `json:"seq"`
	Body    []byte    `json:"body"` // ciphertext. Opaque here, always
	At      time.Time `json:"at"`   // the server's own clock, for expiry only

	// file is the durable copy, when the store has a spool. Unexported, so it
	// is never serialised to a client: which path a relay keeps a message at is
	// the operator's business and nobody else's.
	file string
	// lease and leaseUntil are the collector currently holding this message, if
	// any. Unexported: whose lease a message is under is between the relay and
	// that collector, and a second collector learns only that it is unavailable.
	lease      string
	leaseUntil time.Time
}

// Store holds undelivered messages: in memory, and durably as well when the
// operator has given it somewhere to write.
//
// THE TWO IMPLEMENTATIONS NOW AGREE, and the difference is a deployment choice
// rather than a property of the language. The Worker in edge/ keeps its queue in
// Durable Object storage, which is persistent. This one keeps its queue in
// memory, and also writes each accepted message to a spool directory before
// acknowledging it, if OpenSpool has been called - which the binary does when
// HELIOGRAPH_RELAY_SPOOL is set. Without it, a restart drops whatever had not
// been collected, exactly as this store always has.
//
// Durable is opt-in rather than default because a container with no volume has
// nowhere durable to put anything. Writing into its own filesystem would look
// like durability and provide none, which is the class of claim this file has
// already been wrong about once.
//
// The original argument for memory was that a relay which persisted would be a
// relay with a backup, and a backup of ciphertext is a liability that has to be
// explained to every customer who asks what happens to their data. That is right
// about LONG retention and wrong as "never to disk": a sender that receives a 202
// and deletes its own copy has handed us the only copy, and on this transport the
// sender is often a station nobody can log into. Holding it durably for the few
// seconds until collection is a smaller liability than losing it.
//
// So the retention argument is kept by shortening the window rather than by
// refusing to write: durable on accept, deleted on collection, expired at seven
// days, and never a copy after either. spool.go is the whole of it.
type Store struct {
	mu  sync.Mutex
	q   map[string][]Message // keyed by estate/station/dir
	ttl time.Duration
	max int // per queue, so one estate cannot exhaust the server
	now func() time.Time

	// spool is the durable copy, or nil. nil is the default and behaves exactly
	// as this store always has. See spool.go and OpenSpool.
	spool *spool

	// ids names messages, leases names leases, and epoch separates this run of
	// the process from the last one so that an acknowledgement from before a
	// restart cannot match a lease granted after it. See lease.go.
	ids    uint64
	leases uint64
	epoch  string
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
	// ErrNotDurable means the relay could not write the message where it
	// promised to. The sender is told the message was NOT accepted, because the
	// alternative is telling it the message is safe when the relay knows it is
	// not.
	ErrNotDurable = errors.New("the relay could not store this message durably, so it has not been accepted")
)

func NewStore() *Store {
	return &Store{
		q:   map[string][]Message{},
		ttl: DefaultTTL,
		max: DefaultMaxQueue,
		now: time.Now,
		// The real clock rather than s.now, because this identifies the process
		// rather than a moment in the store's logical time. A test that freezes
		// the clock must still get a different epoch from the run before it.
		epoch: strconv.FormatInt(time.Now().UnixNano(), 36),
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
	m.ID = s.nextIDLocked()

	// Durable before acknowledged, when there is a spool. The order is the whole
	// guarantee: a sender that receives a 202 must never be the only holder of
	// the message, so a message that could not be written is a message that was
	// not accepted, and the error reaches the one side that still has a copy.
	if s.spool != nil {
		file, err := s.spool.write(m)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrNotDurable, err)
		}
		m.file = file
	}
	s.q[k] = append(s.q[k], m)
	return nil
}

// Take returns everything available for a recipient and removes it.
//
// Delete on collection, which is what this has always done and what a request
// without ?lease= still gets. The argument for it was that a second round trip to
// confirm receipt would hold ciphertext for longer, and that a client crashing
// between reading and processing "can simply ask for the step again" - which is
// false, because the message is already deleted. TakeLeased in lease.go is the
// answer to that, and it is opt-in precisely so that this path does not change
// for the stations already deployed.
//
// "Available" means not currently held under somebody's lease. With no leases in
// play, which is every request from a client that has not asked for one, that is
// the whole queue and this is byte for byte the old behaviour. A leased message is
// skipped rather than taken, because a lease that any other collector could
// override would guarantee nothing.
func (s *Store) Take(estate, station, dir string, limit int) ([]Message, error) {
	if !validRoute(estate, station, dir) {
		return nil, ErrBadRoute
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(estate, station, dir)
	s.expireLocked(k)
	s.expireLeasesLocked(k)

	msgs := s.q[k]
	if len(msgs) == 0 {
		return nil, nil
	}
	var taken, kept []Message
	for _, m := range msgs {
		if m.lease != "" || (limit > 0 && len(taken) >= limit) {
			kept = append(kept, m)
			continue
		}
		taken = append(taken, m)
	}
	if len(taken) == 0 {
		return nil, nil
	}
	if len(kept) == 0 {
		delete(s.q, k)
	} else {
		s.q[k] = kept
	}
	s.dropDurableLocked(taken)
	return taken, nil
}

// dropDurableLocked removes the durable copies of messages that have left the
// queue, by collection or by expiry. "Held only until collected, or seven days,
// whichever comes first" has to be true of the disk as well, or durability has
// quietly become a backup of ciphertext - which is the thing the original
// in-memory argument was right about.
func (s *Store) dropDurableLocked(msgs []Message) {
	if s.spool == nil {
		return
	}
	s.spool.remove(msgs...)
}

// Durable reports whether an accepted message survives this process.
//
// It exists so that /health can answer it. A deployment that says which
// guarantee it gives is a deployment nobody has to take on trust, and the
// alternative has already been published and been wrong.
func (s *Store) Durable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spool != nil
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
	if i == 0 {
		return
	}
	s.dropDurableLocked(msgs[:i])
	if i == len(msgs) {
		delete(s.q, k)
		return
	}
	s.q[k] = msgs[i:]
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
