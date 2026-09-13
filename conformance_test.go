package relay_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	relay "github.com/dbhq-uk/heliograph-relay"
	"github.com/dbhq-uk/heliograph-relay/conformance"
)

// The Go server must pass the contract. The Cloudflare Worker in edge/ runs the
// same suite against `wrangler dev` in CI, so the two implementations cannot
// drift without one of them going red.
func TestGoServerPassesTheContract(t *testing.T) {
	auth := relay.NewStaticAuth()
	auth.SetControl("e1", "ctl")
	auth.SetStation("e1", "stn")
	auth.SetControl("e2", "other-ctl")
	auth.SetStation("e2", "other-stn")

	srv := httptest.NewServer(relay.NewServer(relay.NewStore(), auth,
		slog.New(slog.NewTextHandler(io.Discard, nil))).Routes())
	t.Cleanup(srv.Close)

	rs := conformance.Run(conformance.Target{
		BaseURL: srv.URL, Estate: "e1", Station: "st1",
		Control: "ctl", StationTok: "stn",
		OtherEstate: "e2", OtherControl: "other-ctl",
	})
	if !conformance.Report(os.Stdout, "go server", rs) {
		t.Fatal("the Go server does not satisfy the relay contract")
	}
}

// The same contract, with the decision fetched rather than held.
//
// RemoteAuth is the seam the hosted service lives behind, and a seam nobody has
// run the contract through is a seam that will drift from the one everybody
// runs. This pass also supplies the lever the outage section needs, so
// "a control-plane outage is not a bad credential" is asserted over HTTP rather
// than only in a unit test. heliograph-io/heliograph-cloud#7.
func TestTheGoServerPassesTheContractBehindARemoteAuthoriser(t *testing.T) {
	cp := newContractControlPlane(t)
	auth := relay.NewRemoteAuth(cp.url())
	// Long enough that a decision taken before the outage is still good during
	// it, which is the property the section is there to assert.
	auth.Positive = time.Minute

	srv := httptest.NewServer(relay.NewAuthorisingServer(relay.NewStore(), auth,
		slog.New(slog.NewTextHandler(io.Discard, nil))).Routes())
	t.Cleanup(srv.Close)

	rs := conformance.Run(conformance.Target{
		BaseURL: srv.URL, Estate: "e1", Station: "st1",
		Control: "ctl", StationTok: "stn",
		OtherEstate: "e2", OtherControl: "other-ctl",
		ControlPlane: cp.lever,
	})
	if !conformance.Report(os.Stdout, "go server behind a remote authoriser", rs) {
		t.Fatal("the Go server behind RemoteAuth does not satisfy the relay contract")
	}
}

// contractControlPlane answers decisions for the contract's own estates, and
// can be taken away.
//
// It listens on a fixed-for-its-lifetime address rather than using httptest,
// because the outage has to be reversible: httptest.Server cannot be reopened
// once closed, and an outage nobody recovers from proves only half the point.
type contractControlPlane struct {
	ln  net.Listener
	srv *http.Server
	mu  sync.Mutex
}

func newContractControlPlane(t *testing.T) *contractControlPlane {
	t.Helper()
	cp := &contractControlPlane{}
	if err := cp.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cp.stop)
	return cp
}

func (c *contractControlPlane) url() string { return "http://" + c.ln.Addr().String() }

func (c *contractControlPlane) start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	addr := "127.0.0.1:0"
	if c.ln != nil {
		addr = c.ln.Addr().String()
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	c.ln = ln
	c.srv = &http.Server{Handler: http.HandlerFunc(c.decide), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = c.srv.Serve(ln) }()
	return nil
}

func (c *contractControlPlane) stop() {
	c.mu.Lock()
	srv := c.srv
	c.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

func (c *contractControlPlane) lever() func() {
	c.stop()
	return func() { _ = c.start() }
}

var contractTokens = map[string][2]string{
	"e1": {"ctl", "stn"},
	"e2": {"other-ctl", "other-stn"},
}

func (c *contractControlPlane) decide(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Credential string `json:"credential"`
		Estate     string `json:"estate"`
		Dir        string `json:"dir"`
		Op         string `json:"op"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	allow, reason := false, "bad-credential"
	pair, known := contractTokens[in.Estate]
	switch {
	case in.Credential == "":
		reason = "no-credential"
	case !known:
		// An estate nobody configured refuses. Treating an absent entry as a
		// match would authorise everybody.
	case in.Op == "read":
		allow = in.Credential == pair[0] || in.Credential == pair[1]
	case in.Op == "write" && in.Dir == "c2s":
		if in.Credential == pair[1] {
			reason = "wrong-direction"
		}
		allow = in.Credential == pair[0]
	case in.Op == "write" && in.Dir == "s2c":
		if in.Credential == pair[0] {
			reason = "wrong-direction"
		}
		allow = in.Credential == pair[1]
	}
	if allow {
		reason = ""
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"allow": allow, "reason": reason})
}
