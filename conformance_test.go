package relay_test

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"

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
