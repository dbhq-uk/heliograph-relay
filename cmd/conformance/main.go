// Command conformance runs the relay contract against any running relay.
//
// The same suite the Go server's own test runs. Pointing it at `wrangler dev`,
// at a container, or at the hosted relay is how a second implementation earns
// the right to be deployed.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dbhq-uk/heliograph-relay/conformance"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

const usage = `usage: conformance <base-url> [name]

expects estates e1 (ctl/stn) and e2 (other-ctl/other-stn)

  HELIOGRAPH_CONF_CONTROL    e1's control token   (default ctl)
  HELIOGRAPH_CONF_STATION    e1's station token   (default stn)
  HELIOGRAPH_CONF_CONTROL2   e2's control token   (default other-ctl)

  HELIOGRAPH_CONF_AUTHORISER  run a control plane on this address, and assert
                              the outage section. The relay under test must
                              already be pointed at it. Example: 127.0.0.1:9797
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	name := "relay"
	if len(os.Args) > 2 {
		name = os.Args[2]
	}
	// Tokens from the environment, so the same suite can be pointed at a
	// local wrangler, a container, or the hosted relay without editing it.
	ctl := envOr("HELIOGRAPH_CONF_CONTROL", "ctl")
	stn := envOr("HELIOGRAPH_CONF_STATION", "stn")
	ctl2 := envOr("HELIOGRAPH_CONF_CONTROL2", "other-ctl")
	stn2 := envOr("HELIOGRAPH_CONF_STATION2", "other-stn")

	target := conformance.Target{
		BaseURL: os.Args[1], Estate: "e1", Station: "st1",
		Control: ctl, StationTok: stn,
		OtherEstate: "e2", OtherControl: ctl2,
	}

	if addr := os.Getenv("HELIOGRAPH_CONF_AUTHORISER"); addr != "" {
		cp := &controlPlane{addr: addr, tokens: map[string][2]string{
			"e1": {ctl, stn},
			"e2": {ctl2, stn2},
		}}
		if err := cp.start(); err != nil {
			fmt.Fprintf(os.Stderr, "conformance: could not run a control plane on %s: %v\n", addr, err)
			os.Exit(2)
		}
		defer cp.stop()
		target.AuthoriserSaw = cp.Saw
		// The lever. Calling it takes the authoriser away the way a database
		// failure or a bad deployment would, and the returned function puts it
		// back.
		target.ControlPlane = func() (restore func()) {
			cp.stop()
			return func() {
				if err := cp.start(); err != nil {
					fmt.Fprintf(os.Stderr, "conformance: could not restore the control plane: %v\n", err)
				}
				// Give the relay a moment to notice, since a refused
				// connection is only observed on the next attempt.
				time.Sleep(200 * time.Millisecond)
			}
		}
	}

	rs := conformance.Run(target)
	if !conformance.Report(os.Stdout, name, rs) {
		os.Exit(1)
	}
}

// controlPlane answers authorisation decisions for the suite's own estates.
//
// The policy is written out here rather than imported from the Go server, for
// the same reason the conformance package may not import it: the moment the
// harness shares code with one implementation it stops testing the other.
type controlPlane struct {
	addr   string
	tokens map[string][2]string // estate -> {control, station}
	srv    *http.Server
	ln     net.Listener

	// saw is every byte this control plane has been sent, unmodified, so the
	// suite can assert that no message body was ever among them.
	mu  sync.Mutex
	saw []byte
}

// Saw returns everything sent so far.
func (c *controlPlane) Saw() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.saw...)
}

func (c *controlPlane) start() error {
	ln, err := net.Listen("tcp", c.addr)
	if err != nil {
		return err
	}
	c.ln = ln
	c.srv = &http.Server{Handler: http.HandlerFunc(c.decide), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = c.srv.Serve(ln) }()
	return nil
}

func (c *controlPlane) stop() {
	if c.srv != nil {
		_ = c.srv.Close()
		c.srv = nil
	}
}

func (c *controlPlane) decide(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "could not read the decision request", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.saw = append(c.saw, raw...)
	c.mu.Unlock()

	var in struct {
		Credential string `json:"credential"`
		Estate     string `json:"estate"`
		Dir        string `json:"dir"`
		Op         string `json:"op"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		http.Error(w, "could not read the decision request", http.StatusBadRequest)
		return
	}
	allow, reason := false, "bad-credential"
	pair, known := c.tokens[strings.TrimSpace(in.Estate)]
	switch {
	case in.Credential == "":
		reason = "no-credential"
	case !known:
		// An estate nobody configured must refuse. Treating an absent entry as
		// a match would authorise everybody.
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
