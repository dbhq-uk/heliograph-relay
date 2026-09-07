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
	rs := conformance.Run(conformance.Target{
		BaseURL: os.Args[1], Estate: "e1", Station: "st1",
		Control: "ctl", StationTok: "stn",
		OtherEstate: "e2", OtherControl: "other-ctl",
	})
	if !conformance.Report(os.Stdout, name, rs) {
		os.Exit(1)
	}
}
