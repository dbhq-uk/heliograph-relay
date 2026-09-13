package relay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The authorisation surface: every interface an authoriser implements, and so
// every type it is ever handed or asked for.
//
// Adding one here is how a new interface gets covered. Leaving one out is how it
// does not, which is why the list is short and in one place.
var authorisationSurface = []reflect.Type{
	reflect.TypeFor[Admission](),
	reflect.TypeFor[Accounting](),
	reflect.TypeFor[Sessions](),
	reflect.TypeFor[Authoriser](),
	reflect.TypeFor[Auth](),
}

// An authoriser cannot obtain a message body, and this proves it by
// construction rather than by policy.
//
// The strongest sentence this product has is that the thing which is not
// readable never touches your ciphertext. A rule that says an authoriser must
// not look at bodies is worth nothing: somebody adds a field for a good reason,
// nothing fails, and the claim quietly stops being true.
//
// So the proof is in the type system. Every parameter and every return value on
// the authorisation surface is walked transitively, and anything that could
// carry, reference or yield bytes fails: a []byte, a Message, an io.Reader, a
// func, a pointer, an any. An authoriser is handed strings, numbers, times and
// structs of those, and there is nothing it could follow to content.
//
// heliograph-io/heliograph-cloud#68.
func TestAnAuthoriserCannotObtainAMessageBody(t *testing.T) {
	for _, iface := range authorisationSurface {
		for i := range iface.NumMethod() {
			m := iface.Method(i)
			where := iface.Name() + "." + m.Name
			for j := range m.Type.NumIn() {
				checkCarriesNoBody(t, where+" parameter "+m.Type.In(j).String(), m.Type.In(j), nil)
			}
			for j := range m.Type.NumOut() {
				checkCarriesNoBody(t, where+" result "+m.Type.Out(j).String(), m.Type.Out(j), nil)
			}
		}
	}
}

// checkCarriesNoBody fails unless t is provably incapable of carrying bytes.
//
// An allowlist, not a denylist. A denylist would pass anything nobody thought
// of, and the thing nobody thought of is exactly how this claim gets broken.
func checkCarriesNoBody(t *testing.T, where string, typ reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	if seen == nil {
		seen = map[reflect.Type]bool{}
	}
	if seen[typ] {
		return // already established, and this stops a recursive struct looping
	}
	seen[typ] = true

	// time.Time is a struct with a *Location in it, and walking into that would
	// reject it for a pointer that leads to a timezone database. Allowed by
	// name, because it is a clock reading and has no route to a message.
	if typ == reflect.TypeFor[time.Time]() {
		return
	}
	// The one interface allowed through, and it needs its own argument.
	//
	// A context is a value bag, so an authoriser handed the serving request's
	// context could in principle reach whatever the stack put there. The server
	// does not hand it that one: it passes a context with the cancellation and
	// none of the values, and TestTheAuthoriserIsHandedNoValuesFromTheRequest
	// is the assertion.
	if typ == reflect.TypeFor[context.Context]() {
		return
	}
	if typ == reflect.TypeFor[Message]() {
		t.Errorf("%s is a Message, which carries a body", where)
		return
	}

	switch typ.Kind() {
	case reflect.Bool, reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return

	case reflect.Struct:
		for i := range typ.NumField() {
			f := typ.Field(i)
			checkCarriesNoBody(t, where+"."+f.Name, f.Type, seen)
		}

	case reflect.Slice, reflect.Array:
		// A slice of bytes IS a body, whatever it is called. []string is a list
		// of names and is fine; []byte and [N]byte are not.
		if k := typ.Elem().Kind(); k == reflect.Uint8 || k == reflect.Int8 {
			t.Errorf("%s is a slice of bytes, which is what a body is", where)
			return
		}
		checkCarriesNoBody(t, where+"[]", typ.Elem(), seen)

	case reflect.Chan:
		if typ.ChanDir() == reflect.BothDir || typ.ChanDir() == reflect.SendDir {
			// A channel an authoriser can send on is a channel the server reads
			// from, which is a different argument from this one and is not
			// allowed to appear without being made.
			t.Errorf("%s is a channel an authoriser could send on", where)
			return
		}
		checkCarriesNoBody(t, where+"<-", typ.Elem(), seen)

	default:
		// Pointer, map, func, interface, unsafe.Pointer, complex. Each of them
		// is a way to reach something this test cannot see the end of.
		t.Errorf("%s is a %s, which this test cannot prove carries no body", where, typ.Kind())
	}
}

// And the same claim from the other side, empirically.
//
// The reflection test says the types make it impossible. This one hands the
// relay a recognisable pattern of bytes, records literally everything an
// authoriser was given, and fails if the pattern appears anywhere in it. Two
// arguments for one claim, because the claim is the product.
func TestNothingAnAuthoriserIsHandedContainsTheBody(t *testing.T) {
	greedy := &greedyAuthoriser{}
	srv := httptest.NewServer(NewAuthorisingServer(NewStore(), greedy, quiet()).Routes())
	t.Cleanup(srv.Close)

	secret := []byte("SENTINEL-0xFEEDFACE-nobody-should-ever-see-this")
	if r := put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, secret); r.StatusCode != 202 {
		t.Fatalf("put: %d", r.StatusCode)
	}
	if r := do(t, srv, "GET", "/v1/e1/st1/c2s?wait=0", "station-token", nil); r.StatusCode != 200 {
		t.Fatalf("get: %d", r.StatusCode)
	}

	seen, err := json.Marshal(greedy.everything())
	if err != nil {
		t.Fatal(err)
	}
	for _, form := range []string{
		string(secret),
		base64.StdEncoding.EncodeToString(secret),
		strings.ToUpper(base64.StdEncoding.EncodeToString(secret)),
	} {
		if strings.Contains(string(seen), form) {
			t.Fatalf("a message body reached the authoriser: %s", seen)
		}
	}
	if len(greedy.admitted) == 0 || len(greedy.settled) == 0 {
		t.Fatalf("the authoriser was not exercised: %d admissions, %d settlements",
			len(greedy.admitted), len(greedy.settled))
	}
}

// The authoriser is handed the request's cancellation and none of its values.
//
// This is the one hole the reflection test has to exempt. A context is a value
// bag, and the context an http.Handler is given holds whatever the serving
// stack put there. So the server does not pass that one.
func TestTheAuthoriserIsHandedNoValuesFromTheRequest(t *testing.T) {
	greedy := &greedyAuthoriser{}
	srv := httptest.NewServer(NewAuthorisingServer(NewStore(), greedy, quiet()).Routes())
	t.Cleanup(srv.Close)

	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, []byte("x"))
	if len(greedy.contexts) == 0 {
		t.Fatal("the authoriser was never called")
	}
	for _, ctx := range greedy.contexts {
		// A key the serving stack always sets. If the authoriser can read it,
		// it can read anything else the stack or a middleware put there.
		if v := ctx.Value(http.ServerContextKey); v != nil {
			t.Errorf("the authoriser was handed a request value: %v", v)
		}
		// The cancellation still has to work, or a hung authoriser holds a
		// goroutine per abandoned client.
		if ctx.Done() == nil {
			t.Error("the authoriser was handed a context that can never be cancelled")
		}
	}
}

// greedyAuthoriser keeps everything it is ever given, which is the point.
type greedyAuthoriser struct {
	admitted []Request
	settled  []Settlement
	watched  []Request
	contexts []context.Context
}

func (g *greedyAuthoriser) Admit(ctx context.Context, req Request) Grant {
	g.admitted = append(g.admitted, req)
	g.contexts = append(g.contexts, ctx)
	return Grant{Allow: true}
}

func (g *greedyAuthoriser) Settle(ctx context.Context, s Settlement) {
	g.settled = append(g.settled, s)
	g.contexts = append(g.contexts, ctx)
}

func (g *greedyAuthoriser) Watch(ctx context.Context, req Request, _ string) <-chan Reason {
	g.watched = append(g.watched, req)
	g.contexts = append(g.contexts, ctx)
	return nil
}

func (g *greedyAuthoriser) everything() any {
	return map[string]any{
		"admitted": g.admitted,
		"settled":  g.settled,
		"watched":  g.watched,
	}
}

// countingAuthoriser is the smallest thing that records what the server did.
type countingAuthoriser struct {
	grant    Grant
	settled  []Settlement
	revoke   chan Reason
	admitted int
}

func (c *countingAuthoriser) Admit(context.Context, Request) Grant {
	c.admitted++
	g := c.grant
	if g.Reason == ReasonAllowed && !g.Allow {
		g.Allow = true
	}
	return g
}
func (c *countingAuthoriser) Settle(_ context.Context, s Settlement) {
	c.settled = append(c.settled, s)
}
func (c *countingAuthoriser) Watch(context.Context, Request, string) <-chan Reason {
	return c.revoke
}

// Accounting is told what actually moved, after it moved.
//
// Admission sees a declared size, which is what the client claimed before
// anything was read. Charging on that is charging on a number the payer chose.
func TestAccountingIsSettledWithWhatActuallyMoved(t *testing.T) {
	a := &countingAuthoriser{grant: Grant{Allow: true}}
	st := NewStore()
	srv := httptest.NewServer(NewAuthorisingServer(st, a, quiet()).Routes())
	t.Cleanup(srv.Close)

	body := make([]byte, 4096)
	put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, body)
	do(t, srv, "GET", "/v1/e1/st1/c2s?wait=0", "station-token", nil)

	var wrote, read *Settlement
	for i := range a.settled {
		switch a.settled[i].Op {
		case OpWrite:
			wrote = &a.settled[i]
		case OpRead:
			read = &a.settled[i]
		}
	}
	if wrote == nil || read == nil {
		t.Fatalf("expected a settlement for each direction, got %+v", a.settled)
	}
	if wrote.Bytes != 4096 || wrote.Messages != 1 {
		t.Errorf("the write settled as %d bytes in %d messages, want 4096 in 1",
			wrote.Bytes, wrote.Messages)
	}
	if wrote.Outcome != OutcomeAccepted {
		t.Errorf("the write settled as %q, want %q", wrote.Outcome, OutcomeAccepted)
	}
	if read.Bytes != 4096 || read.Messages != 1 {
		t.Errorf("the read settled as %d bytes in %d messages, want 4096 in 1",
			read.Bytes, read.Messages)
	}
	if read.Outcome != OutcomeDelivered {
		t.Errorf("the read settled as %q, want %q", read.Outcome, OutcomeDelivered)
	}
}

// A read that found nothing is settled too, and settled as empty.
//
// An idle station polls for ever. If only deliveries were accounted, the cost
// of holding a connection open would be invisible to whoever is paying for it,
// and the first anybody heard of it would be the bill.
func TestAnEmptyCollectionIsStillAccountedFor(t *testing.T) {
	a := &countingAuthoriser{grant: Grant{Allow: true}}
	srv := httptest.NewServer(NewAuthorisingServer(NewStore(), a, quiet()).Routes())
	t.Cleanup(srv.Close)

	do(t, srv, "GET", "/v1/e1/st1/c2s?wait=0", "station-token", nil)
	if len(a.settled) != 1 {
		t.Fatalf("got %d settlements, want 1", len(a.settled))
	}
	if a.settled[0].Outcome != OutcomeEmpty {
		t.Errorf("an empty collection settled as %q, want %q", a.settled[0].Outcome, OutcomeEmpty)
	}
	if a.settled[0].Bytes != 0 || a.settled[0].Messages != 0 {
		t.Errorf("an empty collection settled as %d bytes in %d messages",
			a.settled[0].Bytes, a.settled[0].Messages)
	}
}

// Admission can cap one operation, below the server's own limit.
//
// A per-operation payload limit is one of the four things the adversarial
// review said a boolean could not express. Without it an account on the
// smallest plan can post 8 MiB per message and the only lever anybody has is
// refusing the account entirely.
func TestAdmissionCanCapOneOperationBelowTheServerLimit(t *testing.T) {
	a := &countingAuthoriser{grant: Grant{Allow: true, MaxBytes: 1024}}
	srv := httptest.NewServer(NewAuthorisingServer(NewStore(), a, quiet()).Routes())
	t.Cleanup(srv.Close)

	if r := put(t, srv, "/v1/e1/st1/c2s", "control-token", 1, make([]byte, 512)); r.StatusCode != 202 {
		t.Errorf("a message inside the cap was refused: %d", r.StatusCode)
	}
	r := put(t, srv, "/v1/e1/st1/c2s", "control-token", 2, make([]byte, 4096))
	if r.StatusCode != 413 {
		t.Errorf("a message over the admission cap answered %d, want 413", r.StatusCode)
	}
	var why struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&why)
	if why.Reason != string(ReasonTooLarge) {
		t.Errorf("reason %q, want %q", why.Reason, ReasonTooLarge)
	}
}

// Revoking authority ends a poll that is already open.
//
// "Authorise every call" says nothing about a connection that is already held,
// and a long poll is held for 25 seconds by design. Without this, revocation
// means "revoked at some point in the next half minute, or longer if the
// station reconnects at the wrong moment".
func TestRevokingAuthorityEndsAPollThatIsAlreadyOpen(t *testing.T) {
	revoke := make(chan Reason, 1)
	a := &countingAuthoriser{grant: Grant{Allow: true}, revoke: revoke}
	srv := httptest.NewServer(NewAuthorisingServer(NewStore(), a, quiet()).Routes())
	t.Cleanup(srv.Close)

	type result struct {
		code   int
		reason string
	}
	done := make(chan result, 1)
	go func() {
		r := do(t, srv, "GET", "/v1/e1/st1/c2s", "station-token", nil)
		var why struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&why)
		done <- result{r.StatusCode, why.Reason}
	}()
	time.Sleep(150 * time.Millisecond) // let the poll get in and wait
	revoke <- ReasonRevoked

	select {
	case got := <-done:
		if got.code != 401 {
			t.Errorf("a revoked poll answered %d, want 401", got.code)
		}
		if got.reason != string(ReasonRevoked) {
			t.Errorf("a revoked poll said %q, want %q", got.reason, ReasonRevoked)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revoking authority did not end a poll that was already open")
	}
}

// A poll that is never revoked still answers on its own timer. A nil channel
// blocks for ever, which is the correct zero value, and it must not become a
// poll that never returns.
func TestAPollWithNoRevocationChannelStillTimesOut(t *testing.T) {
	a := &countingAuthoriser{grant: Grant{Allow: true}} // revoke is nil
	s := NewAuthorisingServer(NewStore(), a, quiet())
	s.wait = 200 * time.Millisecond
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)

	start := time.Now()
	r := do(t, srv, "GET", "/v1/e1/st1/c2s", "station-token", nil)
	if r.StatusCode != 200 {
		t.Errorf("got %d", r.StatusCode)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("the poll took %v, so a nil revocation channel blocked it", d)
	}
	_, _ = io.Copy(io.Discard, r.Body)
}
