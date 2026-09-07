// Command conformance runs the relay contract against any running relay.
//
// The same suite the Go server's own test runs. Pointing it at `wrangler dev`,
// at a container, or at the hosted relay is how a second implementation earns
// the right to be deployed.
package main

import (
	"fmt"
	"os"

	"github.com/dbhq-uk/heliograph-relay/conformance"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: conformance <base-url> [name]")
		fmt.Fprintln(os.Stderr, "\nexpects estates e1 (ctl/stn) and e2 (other-ctl/other-stn)")
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
	rs := conformance.Run(conformance.Target{
		BaseURL: os.Args[1], Estate: "e1", Station: "st1",
		Control: ctl, StationTok: stn,
		OtherEstate: "e2", OtherControl: envOr("HELIOGRAPH_CONF_CONTROL2", "other-ctl"),
	})
	if !conformance.Report(os.Stdout, name, rs) {
		os.Exit(1)
	}
}
