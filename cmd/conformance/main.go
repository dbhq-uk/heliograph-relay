// Command conformance runs the relay contract against any running relay.
//
// The same suite the Go server's own test runs. Pointing it at `wrangler dev`,
// at a container, or at the hosted relay is how a second implementation earns
// the right to be deployed.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/heliograph-io/heliograph-relay/conformance"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// restart is a command that stops the relay and starts it again with whatever it
// holds durably intact.
//
// The suite cannot do this itself, and should not be able to: a conformance
// suite able to restart its target is a conformance suite somebody will
// eventually point at a production relay. So the mechanism is the harness's, it
// is named on the command line, and without it the durability assertions report
// as skipped rather than as passed.
var restart = flag.String("restart", "",
	"shell command that restarts the relay, keeping its durable state.\n"+
		"Supplying it enables the durability assertions; without it they are skipped.\n"+
		"See scripts/restart-go-relay.sh and scripts/restart-worker.sh.")

var health = flag.Duration("restart-timeout", 90*time.Second,
	"how long to wait for /health after a restart")

const usage = `usage: conformance [-restart <command>] <base-url> [name]

expects estates e1 (ctl/stn) and e2 (other-ctl/other-stn)

  HELIOGRAPH_CONF_CONTROL    e1's control token   (default ctl)
  HELIOGRAPH_CONF_STATION    e1's station token   (default stn)
  HELIOGRAPH_CONF_CONTROL2   e2's control token   (default other-ctl)

  HELIOGRAPH_CONF_AUTHORISER  run a control plane on this address, and assert
                              the outage section. The relay under test must
                              already be pointed at it. Example: 127.0.0.1:9797
  HELIOGRAPH_CONF_TENANCY     the relay under test refuses estate-wide
                              credentials, so assert per-station isolation too

The relay under test should be started with its lease verification key set to
the contract's published public key, or the signed-lease section is skipped:

  HELIOGRAPH_RELAY_LEASE_KEY=79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664
`

func main() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}
	base := flag.Arg(0)
	name := "relay"
	if flag.NArg() > 1 {
		name = flag.Arg(1)
	}
	// Tokens from the environment, so the same suite can be pointed at a
	// local wrangler, a container, or the hosted relay without editing it.
	ctl := envOr("HELIOGRAPH_CONF_CONTROL", "ctl")
	stn := envOr("HELIOGRAPH_CONF_STATION", "stn")
	ctl2 := envOr("HELIOGRAPH_CONF_CONTROL2", "other-ctl")
	stn2 := envOr("HELIOGRAPH_CONF_STATION2", "other-stn")

	target := conformance.Target{
		BaseURL: base, Estate: "e1", Station: "st1",
		Control: ctl, StationTok: stn,
		OtherEstate: "e2", OtherControl: ctl2,
	}

	// Two levers, and neither belongs in the suite itself: one takes the
	// authoriser away, one takes the whole relay away. Both are supplied here
	// because the harness knows how this deployment is run and the contract
	// deliberately does not.
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
		// The per-station isolation section only means anything against a relay
		// that refuses estate-wide credentials, so the harness has to be told
		// the relay under test was started that way.
		target.Tenancy = os.Getenv("HELIOGRAPH_CONF_TENANCY") != ""
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
	if *restart != "" {
		target.Disrupt = restarter(base, *restart, *health)
	}

	// The harness signs, and the relay under test only verifies. This is the
	// one place in the repository that holds a private key, it is a published
	// test fixture rather than a secret, and it is never deployed.
	//
	// TestTheSigningCheckCanTellASignerFromAVerifier builds THIS binary and
	// fails if it does not link a signing path, which is how the check on the
	// relay binary is known to discriminate rather than merely pass.
	if seed, err := hex.DecodeString(conformance.LeaseSeed); err == nil && len(seed) == ed25519.SeedSize {
		priv := ed25519.NewKeyFromSeed(seed)
		target.SignLease = func(payload string) []byte {
			return ed25519.Sign(priv, []byte(payload))
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
		Station    string `json:"station"`
		Dir        string `json:"dir"`
		Op         string `json:"op"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		http.Error(w, "could not read the decision request", http.StatusBadRequest)
		return
	}
	// The tenancy credentials are answered first, because they are bound to one
	// station each and an ordinary estate lookup would not see that.
	if sc, ok := scopeFor(in.Credential, in.Estate, in.Station, in.Dir, in.Op); ok {
		reply(w, true, "", sc)
		return
	}
	if _, bound := tenancy[in.Credential]; bound {
		reply(w, false, "out-of-scope", nil)
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
	if !allow {
		reply(w, false, reason, nil)
		return
	}
	// Station-scoped, for the station being asked about. A per-request
	// authoriser grants exactly one station at a time, and saying so is what
	// lets a hosted relay tell a narrow grant from a wide one.
	read, write := []string{"s2c"}, []string{"c2s"}
	if in.Credential == pair[1] {
		read, write = []string{"c2s"}, []string{"s2c"}
	}
	reply(w, true, "", stationScope(in.Estate, in.Station, read, write))
}

// reply writes one decision.
func reply(w http.ResponseWriter, allow bool, reason string, scope map[string]any) {
	out := map[string]any{"allow": allow, "reason": reason}
	if scope != nil {
		out["scope"] = scope
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// tenancy is the two-customer policy the contract's per-station section needs.
//
// Two customers under ONE estate identifier, each credential bound to its own
// station. That binding is the whole point: a relay that granted whatever
// station was asked for would pass the isolation section without enforcing
// anything.
var tenancy = map[string]struct {
	station string
	read    []string
	write   []string
}{
	conformance.TenantAlphaStation: {conformance.TenantAlpha, []string{"c2s"}, []string{"s2c"}},
	conformance.TenantAlphaControl: {conformance.TenantAlpha, []string{"s2c"}, []string{"c2s"}},
	conformance.TenantBravoStation: {conformance.TenantBravo, []string{"c2s"}, []string{"s2c"}},
	conformance.TenantBravoControl: {conformance.TenantBravo, []string{"s2c"}, []string{"c2s"}},
}

// scopeFor answers the scope half of a decision.
//
// Ordinary estates are answered station-scoped for the station being asked
// about, which is what a per-request authoriser genuinely grants. The tenancy
// credentials are answered from their binding, and TenantWide is answered
// estate-wide on purpose so a hosted relay has something to refuse.
func scopeFor(credential, estate, station, dir, op string) (map[string]any, bool) {
	if credential == conformance.TenantWide {
		return map[string]any{
			"estate": estate, "stations": []string{}, "allStations": true,
			"read": []string{"c2s", "s2c"}, "write": []string{"c2s", "s2c"},
		}, true
	}
	if t, ok := tenancy[credential]; ok {
		if estate != conformance.TenantEstate || station != t.station {
			return nil, false
		}
		allowed := t.read
		if op == "write" {
			allowed = t.write
		}
		if !slices.Contains(allowed, dir) {
			return nil, false
		}
		return map[string]any{
			"estate": estate, "stations": []string{t.station}, "allStations": false,
			"read": t.read, "write": t.write,
		}, true
	}
	return nil, false
}

// stationScope narrows an ordinary estate decision to the station asked about.
func stationScope(estate, station string, read, write []string) map[string]any {
	return map[string]any{
		"estate": estate, "stations": []string{station}, "allStations": false,
		"read": read, "write": write,
	}
}

// restarter runs the command and then waits for the relay to answer again.
//
// Waiting here rather than in the script means every harness waits the same way,
// and a script that returns the moment it has forked does not turn into a
// flaky durability failure.
func restarter(base, command string, timeout time.Duration) conformance.Disrupt {
	return func() error {
		cmd := exec.Command("sh", "-c", command)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("the restart command failed: %w", err)
		}
		client := &http.Client{Timeout: 5 * time.Second}
		deadline := time.Now().Add(timeout)
		for {
			resp, err := client.Get(base + "/health")
			if err == nil {
				code := resp.StatusCode
				_ = resp.Body.Close()
				if code == http.StatusOK {
					return nil
				}
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("the relay did not answer /health within %s of the restart", timeout)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
}
