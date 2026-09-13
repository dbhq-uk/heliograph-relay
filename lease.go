package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Leased collection: hold the message until the collector says it has it.
//
// WHAT IT IS FOR. Take returns a queue and deletes it in the same breath. The
// comment defending that said a client which crashes between reading and
// processing "can simply ask for the step again" - and that is wrong, because the
// message has already gone. The window between the relay's delete and the
// collector's durable write is a loss window, and on this transport what is in it
// is frequently the only copy of a capture from a machine nobody can log into.
//
// So: GET with ?lease=30s marks the messages instead of deleting them, and they
// are deleted when the collector acknowledges. A collector that dies never
// acknowledges, the lease expires, and the messages are collectable again.
//
// OPT-IN, AND THAT IS A COMPATIBILITY GUARANTEE RATHER THAN A CONVENIENCE.
// Without ?lease= the answer is byte for byte what it was: a bare JSON array, and
// the queue deleted. Every station already deployed fetches exactly that.
//
// NO CRYPTOGRAPHY, because there is none in this package and a lease does not
// need any. A lease id is a counter and a process epoch, not a token: it proves
// nothing and is not relied on to. Acknowledging takes the same credential as
// collecting, so guessing an id gains an attacker who has no credential nothing,
// and one who does can already collect destructively.
//
// heliograph-io/heliograph-cloud#9.

// MaxLease is the longest lease the relay will grant.
//
// Tens of seconds is the design: a collector writes to its own spool and
// acknowledges immediately, so a long lease only means a longer wait before an
// abandoned message comes back. Five minutes is a ceiling rather than a target,
// and a request for more is refused rather than silently clamped - a collector
// that thinks it has an hour would behave differently from one that knows it has
// five minutes.
const MaxLease = 5 * time.Minute

var (
	// ErrNoSuchLease means the relay is not holding that lease: it expired, it was
	// already acknowledged, or it never existed. A collector's safe response is
	// the same in all three cases, which is to expect redelivery.
	ErrNoSuchLease  = errors.New("the relay is not holding that lease, so the messages may already have been returned to the queue")
	ErrBadLease     = errors.New("a lease must be a duration, like 30s")
	ErrLeaseTooLong = fmt.Errorf("a lease may not be longer than %s", MaxLease)
)

// Lease is what a collector holds between reading messages and confirming it has
// them.
type Lease struct {
	ID       string    `json:"lease"`
	Until    time.Time `json:"until"`
	Messages []Message `json:"messages"`
}

// MarshalJSON writes an EMPTY until when there is no lease, rather than Go's
// zero time.
//
// Without this the two implementations answer an empty leased collection
// differently: "0001-01-01T00:00:00Z" here and "" in the Worker, which is drift
// in a field a client reads. Found by driving both with curl rather than by a
// test, so the contract now asserts it - see conformance/, "an empty leased
// collection says so in both fields".
func (l Lease) MarshalJSON() ([]byte, error) {
	until := ""
	if !l.Until.IsZero() {
		until = l.Until.Format(time.RFC3339Nano)
	}
	msgs := l.Messages
	if msgs == nil {
		msgs = []Message{}
	}
	return json.Marshal(struct {
		ID       string    `json:"lease"`
		Until    string    `json:"until"`
		Messages []Message `json:"messages"`
	}{ID: l.ID, Until: until, Messages: msgs})
}

// ParseLease reads the ?lease= parameter.
//
// THE GRAMMAR IS SMALL ON PURPOSE, and it is the whole specification of this
// parameter:
//
//	lease  = "" | "0" | number unit?
//	number = digits [ "." digits ]
//	unit   = "ms" | "s" | "m" | "h"      default "s"
//
// Empty and "0" both mean no lease, so a client building its query string from a
// variable does not change the semantics of collection by leaving the variable
// empty. A bare number is seconds, because a parameter typed into a shell script
// should not need a unit to be understood.
//
// time.ParseDuration is deliberately NOT used, even though this is Go and it is
// right there. It accepts compound durations like "1m30s", and the Worker
// implements this same parameter: inheriting a quirk here would mean ?lease=1m30s
// worked against one implementation and 400ed against the other, which is exactly
// the drift conformance/ exists to prevent. Anything outside this grammar is
// refused rather than guessed at.
func ParseLease(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" || v == "0" {
		return 0, nil
	}
	unit := time.Second
	switch {
	case strings.HasSuffix(v, "ms"):
		unit, v = time.Millisecond, strings.TrimSuffix(v, "ms")
	case strings.HasSuffix(v, "s"):
		unit, v = time.Second, strings.TrimSuffix(v, "s")
	case strings.HasSuffix(v, "m"):
		unit, v = time.Minute, strings.TrimSuffix(v, "m")
	case strings.HasSuffix(v, "h"):
		unit, v = time.Hour, strings.TrimSuffix(v, "h")
	}
	if v == "" || strings.ContainsAny(v, "eE+- \t") {
		// No exponents, no signs, no spaces. A lease is a small positive number
		// and anything clever in it is a client bug worth reporting rather than
		// interpreting.
		return 0, ErrBadLease
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil || n < 0 {
		return 0, ErrBadLease
	}
	d := time.Duration(n * float64(unit))
	// One place for the bounds, after every form has been read. The first version
	// checked the ceiling only on the form with a unit, so lease=600 was accepted
	// as ten minutes here and refused later by TakeLeased: two rules where there
	// should be one.
	if d > MaxLease {
		return 0, ErrLeaseTooLong
	}
	return d, nil
}

// TakeLeased hands out messages without deleting them.
//
// The messages stay where they are in the queue, marked. That is deliberate: an
// expiring lease then returns them in their original position rather than at the
// back, so a collector that dies does not reorder the queue for whoever collects
// next. Ordering is the recipient's business, but handing it an avoidable mess
// would be this server's fault.
func (s *Store) TakeLeased(estate, station, dir string, limit int, d time.Duration) (Lease, error) {
	if !validRoute(estate, station, dir) {
		return Lease{}, ErrBadRoute
	}
	if d <= 0 {
		return Lease{}, ErrBadLease
	}
	if d > MaxLease {
		return Lease{}, ErrLeaseTooLong
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(estate, station, dir)
	s.expireLocked(k)
	s.expireLeasesLocked(k)

	msgs := s.q[k]
	id := s.nextLeaseLocked()
	until := s.now().Add(d)
	var held []Message
	for i := range msgs {
		if msgs[i].lease != "" {
			continue // somebody else is holding it
		}
		if limit > 0 && len(held) >= limit {
			break
		}
		msgs[i].lease = id
		msgs[i].leaseUntil = until
		held = append(held, msgs[i])
	}
	if len(held) == 0 {
		// No lease id for an empty answer. A collector with nothing to
		// acknowledge must not be handed something to acknowledge.
		return Lease{Messages: []Message{}}, nil
	}
	return Lease{ID: id, Until: until, Messages: held}, nil
}

// Ack deletes the messages held under a lease, and their durable copies.
func (s *Store) Ack(estate, station, dir, id string) (int, error) {
	if !validRoute(estate, station, dir) {
		return 0, ErrBadRoute
	}
	if strings.TrimSpace(id) == "" {
		return 0, ErrNoSuchLease
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(estate, station, dir)
	s.expireLocked(k)
	s.expireLeasesLocked(k)

	msgs := s.q[k]
	var acked, kept []Message
	for _, m := range msgs {
		if m.lease == id {
			acked = append(acked, m)
			continue
		}
		kept = append(kept, m)
	}
	if len(acked) == 0 {
		return 0, ErrNoSuchLease
	}
	if len(kept) == 0 {
		delete(s.q, k)
	} else {
		s.q[k] = kept
	}
	s.dropDurableLocked(acked)
	return len(acked), nil
}

// expireLeasesLocked releases leases whose deadline has passed.
//
// Lazily, on the next access, as TTL expiry already works here. A sweeper would
// be a second mechanism to get wrong, and nothing observes a released lease
// except the next collection.
func (s *Store) expireLeasesLocked(k string) {
	msgs := s.q[k]
	now := s.now()
	for i := range msgs {
		if msgs[i].lease != "" && !msgs[i].leaseUntil.After(now) {
			msgs[i].lease = ""
			msgs[i].leaseUntil = time.Time{}
		}
	}
}

// nextLeaseLocked returns an id no previous run of this process can collide with.
//
// The epoch matters. Leases live in memory here, so a restart releases them - the
// safe direction, since the messages become collectable again. But a collector
// whose acknowledgement arrives after that restart must NOT delete whatever the
// next collector is now holding, and with a bare counter it would: the new run
// would hand out the same ids. The epoch makes a stale acknowledgement a 410
// instead of somebody else's silent loss.
func (s *Store) nextLeaseLocked() string {
	s.leases++
	return fmt.Sprintf("%s-%d", s.epoch, s.leases)
}

// nextIDLocked returns the id a message keeps for as long as it exists.
//
// Stable across redelivery, which is what a collector deduplicates on: an expired
// lease followed by a successful one delivers the same message twice, and the
// collector has to be able to tell that it is the same message. Unique within its
// route; ids from different routes are not comparable and are not meant to be.
func (s *Store) nextIDLocked() string {
	s.ids++
	return "m" + strconv.FormatUint(s.ids, 10)
}
