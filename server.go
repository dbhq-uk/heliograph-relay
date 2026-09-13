package relay

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server is the HTTP surface.
//
// Long-poll, not WebSocket. Paseo uses WebSocket because its daemon runs where
// the user controls the network; a heliograph station runs behind a corporate
// proxy that may strip an upgrade header, and a transport that fails on those
// estates fails on exactly the estates this is for.
type Server struct {
	store *Store
	auth  Authoriser
	log   *slog.Logger

	// wait is how long a poll holds the line before answering empty. Long
	// enough that an idle loop is nearly free, short enough that a proxy with
	// its own idle timeout does not cut it first.
	wait time.Duration

	mu      sync.Mutex
	waiters map[string][]chan struct{}

	// Version is what this build reports at /version and /. Empty means
	// nobody set it, which is itself worth reporting rather than hiding:
	// an operator who cannot tell what is deployed should be told so.
	Version string

	// Hash is the SHA-256 of the artefact that is serving, reported at
	// /health, and it answers a different question from Version.
	//
	// A version is a NAME a deployment gives itself: whoever deployed can
	// pass any string they like, and a hand-deploy did exactly that before
	// there was a workflow. A hash is a NUMBER somebody else can arrive at,
	// by building the same tag and comparing - which is the only form of
	// "the relay in the path is the relay you read" that does not end in
	// trusting the operator. See https://heliograph.dbhq.uk/provenance.
	//
	// Empty means nobody could work it out, and /health says "unknown"
	// rather than an empty string, for the same reason Version does.
	Hash string
}

// Auth decides whether a token may act on a route.
//
// Deliberately small, and deliberately NOT a security boundary for content or
// execution. A stolen token can never produce plaintext and can never cause a
// station to run anything, because both of those are settled by signatures this
// server cannot make. Saying that plainly matters, because "we use scoped
// tokens" is exactly the sort of claim that gets mistaken for the real
// protection.
//
// It IS the boundary for four things, and they are the ones an operator paying
// for the transport notices: collection, availability, tenant isolation and
// whatever is being metered. Collection is the sharp one. Store.Take deletes in
// the same breath as it returns (relay.go:131), so a stolen token causes silent
// LOSS rather than silent disclosure - and on this transport the sender is
// often a station nobody can log into, holding the only copy. The unqualified
// sentence that used to be here read as "token handling is unimportant", which
// is wrong in exactly the case somebody is paying for.
//
// Reading and writing are separate methods rather than one method and a
// type assertion. The first version had the write restriction behind
// `if sa, ok := auth.(*StaticAuth)`, which meant any other implementation
// silently skipped it - a station able to queue requests, reachable by
// swapping in a different Auth. A rule that only applies to one concrete type
// is not a rule.
type Auth interface {
	// AllowRead reports whether this token may collect from this queue.
	AllowRead(token, estate, station, dir string) bool
	// AllowWrite reports whether this token may put onto it. Asymmetric on
	// purpose: a station must not be able to queue a request, even for itself.
	AllowWrite(token, estate, station, dir string) bool
}

// StaticAuth is the self-hosted default: one token per estate for each side.
type StaticAuth struct {
	// hashed, so a memory dump or a config listing does not hand over a live
	// credential. Compared in constant time.
	control map[string][32]byte // estate -> sha256(token)
	station map[string][32]byte
}

func NewStaticAuth() *StaticAuth {
	return &StaticAuth{control: map[string][32]byte{}, station: map[string][32]byte{}}
}

func (a *StaticAuth) SetControl(estate, token string) {
	a.control[estate] = sha256.Sum256([]byte(token))
}
func (a *StaticAuth) SetStation(estate, token string) {
	a.station[estate] = sha256.Sum256([]byte(token))
}

// Allow enforces the two scopes.
//
// A control may write requests and read what the station published. A station
// may read requests and write status and logs. Neither may do the other's half,
// so a station token stolen from a machine nobody can reach cannot be used to
// queue a request for any station, including its own.
func (a *StaticAuth) AllowRead(token, estate, station, dir string) bool {
	if token == "" || estate == "" || station == "" || !validDir(dir) {
		return false
	}
	got := sha256.Sum256([]byte(token))
	// Either side may read either queue of its own estate. A control reading
	// back what it queued is harmless, and refusing it would buy nothing.
	return match(a.control[estate], got) || match(a.station[estate], got)
}

// AllowWrite is the one that matters.
//
// A station token sits on a machine nobody can reach and cannot be rotated
// quickly. If it could queue a c2s message, a stolen one would let an attacker
// send requests to that station - and the station would then refuse them,
// because they would not carry the control signature. But it would fill the
// queue, and it would mean the relay's own credential could cause traffic the
// control never sent. Neither is acceptable when the fix is one method.
func (a *StaticAuth) AllowWrite(token, estate, station, dir string) bool {
	if token == "" || estate == "" || station == "" {
		return false
	}
	got := sha256.Sum256([]byte(token))
	switch dir {
	case "c2s":
		return match(a.control[estate], got)
	case "s2c":
		return match(a.station[estate], got)
	}
	return false
}

func validDir(d string) bool { return d == "c2s" || d == "s2c" }

func match(want, got [32]byte) bool {
	var zero [32]byte
	if want == zero {
		return false // no token configured for this estate
	}
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}

// NewServer takes the boolean Auth, which is what a self-hoster writes, and
// lifts it onto the Authoriser seam.
func NewServer(store *Store, auth Auth, log *slog.Logger) *Server {
	return NewAuthorisingServer(store, FromAuth(auth), log)
}

// NewAuthorisingServer takes the wider seam, which is what the hosted service
// and anybody else with a control plane uses.
func NewAuthorisingServer(store *Store, auth Authoriser, log *slog.Logger) *Server {
	return &Server{
		store:   store,
		auth:    auth,
		log:     log,
		wait:    25 * time.Second,
		waiters: map[string][]chan struct{}{},
	}
}

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/{estate}/{station}/{dir}", s.put)
	mux.HandleFunc("GET /v1/{estate}/{station}/{dir}", s.get)
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /version", s.version)
	mux.HandleFunc("GET /{$}", s.root)
	return mux
}

// health is what a monitoring check hits, and it now carries the two things
// such a check has no other way to learn: which version is answering, and the
// hash of the artefact answering.
//
// `ok` stays first and stays a boolean, because something out there is already
// looking for it and this endpoint is not the place to make somebody's alert
// stop working.
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"ok":      true,
		"version": s.reportedVersion(),
		"hash":    s.reportedHash(),
	})
}

// reportedVersion never returns an empty string. A build with no version
// stamped says so, because "unknown" is a true answer an operator can act on
// and a blank field reads as a bug in the client asking.
func (s *Server) reportedVersion() string {
	if s.Version == "" {
		return "unknown"
	}
	return s.Version
}

// reportedHash never returns an empty string, for the same reason
// reportedVersion does not: "unknown" is a true answer somebody can act on.
func (s *Server) reportedHash() string {
	if s.Hash == "" {
		return "unknown"
	}
	return s.Hash
}

// version exists so that "the relay you are talking to is the relay you read"
// is checkable rather than asserted. Without it nobody, including whoever
// deployed it, can tell which commit is answering.
func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{
		"service":        "heliograph-relay",
		"implementation": "go",
		"version":        s.reportedVersion(),
		"source":         sourceURL,
	})
}

// root answers the one request a human makes. Somebody who found this
// hostname in a config file and pasted it into a browser used to get
// {"error":"no such route"} - and because that carried a JSON content type,
// mobile Safari offered it as a 25-byte download rather than showing it.
//
// So a browser gets a page and everything else gets JSON. The JSON half
// matters: / is also how a check reads the version.
func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, landingHTML, shortWhat, s.reportedVersion(), sourceURL, docsURL)
		return
	}
	writeJSON(w, map[string]string{
		"service":        "heliograph-relay",
		"implementation": "go",
		"version":        s.reportedVersion(),
		"what":           whatItIs,
		"source":         sourceURL,
		"docs":           docsURL,
	})
}

const (
	whatItIs  = "Stores and forwards opaque ciphertext between a control and a station. It holds no keys, does no crypto, and never sees plaintext."
	sourceURL = "https://github.com/dbhq-uk/heliograph-relay"
	docsURL   = "https://heliograph.dbhq.uk/relay"

	// The page a person lands on gets the short form. The full description is
	// still the honest one and stays in the JSON, where length costs nothing
	// and a machine is reading it anyway.
	shortWhat = "Stores and forwards ciphertext it cannot read."

	landingHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>heliograph relay</title>
<style>
 body{background:#111;color:#eee;font:15px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;padding:2.5rem 1.25rem;max-width:34rem}
 h1{font-size:1rem;margin:0;font-weight:600}
 p{color:#8b8b8b;margin:.25rem 0 1.75rem}
 a{color:#6cf;display:block}
 code{color:#8b8b8b;word-break:break-all}
</style></head><body>
<h1>heliograph relay</h1>
<p>%s</p>
<code>%s</code>
<a href="%s">source</a>
<a href="%s">docs</a>
</body></html>`
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// token reads the bearer credential.
func token(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}

func (s *Server) put(w http.ResponseWriter, r *http.Request) {
	estate, station, dir := r.PathValue("estate"), r.PathValue("station"), r.PathValue("dir")
	// The direction is route shape, not credential scope, so it is refused
	// before the authoriser is asked and refused as a 400. The Worker has
	// always done it in this order (edge/src/worker.ts:278) and the Go server
	// answered 401, which is two implementations disagreeing about whose fault
	// a typo is.
	if !validDir(dir) {
		refuse(w, Grant{Reason: ReasonBadRoute})
		return
	}
	g := s.auth.Admit(r.Context(), Request{
		Credential: token(r), Estate: estate, Station: station, Dir: dir,
		Op: OpWrite, Bytes: r.ContentLength, At: time.Now(),
	})
	if !g.Allow {
		s.refused(g, estate, station, dir, OpWrite)
		refuse(w, g)
		return
	}

	body := http.MaxBytesReader(w, r.Body, MaxBodyBytes+1024)
	var in struct {
		Seq  uint64 `json:"seq"`
		Body []byte `json:"body"`
	}
	if err := json.NewDecoder(body).Decode(&in); err != nil {
		refuse(w, Grant{Reason: ReasonUnreadable})
		return
	}
	err := s.store.Put(Message{
		Estate: estate, Station: station, Dir: dir, Seq: in.Seq, Body: in.Body,
	})
	switch {
	case errors.Is(err, ErrTooLarge):
		refuse(w, Grant{Reason: ReasonTooLarge, Detail: err.Error()})
		return
	case errors.Is(err, ErrQueueFull):
		// 429 rather than 500: it is the sender's problem to slow down, and a
		// 5xx would send them looking for a fault on this side.
		refuse(w, Grant{Reason: ReasonQueueFull, Detail: err.Error()})
		return
	case errors.Is(err, ErrBadRoute):
		refuse(w, Grant{Reason: ReasonBadRoute, Detail: err.Error()})
		return
	case err != nil:
		refuse(w, Grant{Reason: ReasonInternal})
		return
	}

	// Metadata only. Never the body, never a token, not even its length in a
	// way that could be reassembled into content.
	s.log.Info("put", "estate", estate, "station", station, "dir", dir,
		"bytes", len(in.Body))
	s.wake(key(estate, station, dir))
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	estate, station, dir := r.PathValue("estate"), r.PathValue("station"), r.PathValue("dir")
	if !validDir(dir) {
		refuse(w, Grant{Reason: ReasonBadRoute})
		return
	}
	g := s.auth.Admit(r.Context(), Request{
		Credential: token(r), Estate: estate, Station: station, Dir: dir,
		Op: OpRead, At: time.Now(),
	})
	if !g.Allow {
		s.refused(g, estate, station, dir, OpRead)
		refuse(w, g)
		return
	}
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, _ = strconv.Atoi(v)
	}

	msgs, err := s.store.Take(estate, station, dir, limit)
	if err != nil {
		refuse(w, Grant{Reason: ReasonBadRoute, Detail: err.Error()})
		return
	}
	if len(msgs) == 0 && r.URL.Query().Get("wait") != "0" {
		// Long-poll. An idle station costs one held connection rather than a
		// request every few seconds, which is what makes a poll interval of
		// "immediately" affordable on a link somebody is paying for.
		if s.hold(r, key(estate, station, dir)) {
			msgs, _ = s.store.Take(estate, station, dir, limit)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if msgs == nil {
		msgs = []Message{}
	}
	_ = json.NewEncoder(w).Encode(msgs)
}

// hold waits for a message, the timeout, or the client going away.
func (s *Server) hold(r *http.Request, k string) bool {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.waiters[k] = append(s.waiters[k], ch)
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		w := s.waiters[k]
		for i, c := range w {
			if c == ch {
				s.waiters[k] = append(w[:i], w[i+1:]...)
				break
			}
		}
		if len(s.waiters[k]) == 0 {
			delete(s.waiters, k)
		}
		s.mu.Unlock()
	}()

	timer := time.NewTimer(s.wait)
	defer timer.Stop()
	select {
	case <-ch:
		return true
	case <-timer.C:
		return false
	case <-r.Context().Done():
		// The client hung up. Returning rather than holding the goroutine is
		// what stops a flapping link accumulating them.
		return false
	}
}

func (s *Server) wake(k string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.waiters[k] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// refuse writes a refusal, and every refusal carries a machine-readable reason
// beside the sentence.
//
// The sentence is for a person and the reason is for a program, and the two are
// separate fields because a client that has to match on English prose is a
// client that breaks when the prose improves.
func refuse(w http.ResponseWriter, g Grant) {
	if g.Reason == ReasonAllowed {
		// A refusal that names no reason must still refuse. This is not
		// hypothetical: the first version of RemoteAuth returned a bare
		// Grant{Allow: false} on an unreachable authoriser, and because the
		// zero Reason is "allowed", Status() answered 200 and the relay handed
		// out a success with an error body in it. The test that caught it is
		// TestARefusalWithNoReasonStillRefuses.
		g.Reason = ReasonBadCredential
	}
	detail := g.Detail
	if detail == "" {
		detail = g.Reason.Detail()
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(g.Reason.Status())
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  detail,
		"reason": string(g.Reason),
	})
}

// refused logs a refusal. Metadata only, and the reason, because the reason is
// what an operator watching a graph needs: a rise in authoriser-unavailable is
// our fault and a rise in bad-credential is somebody else's.
func (s *Server) refused(g Grant, estate, station, dir string, op Op) {
	s.log.Info("refused", "estate", estate, "station", station, "dir", dir,
		"op", string(op), "reason", string(g.Reason), "status", g.Reason.Status())
}

// FingerprintToken is for an operator who has to say which token is configured
// without saying what it is.
func FingerprintToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])[:12]
}
