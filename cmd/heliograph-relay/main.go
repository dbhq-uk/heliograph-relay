// Command heliograph-relay runs the relay.
//
// Configuration is environment only, and tokens are read as hashes into memory
// at start. There is no admin API and no way to ask the running server what a
// token is, because there is no reason for one to exist and every reason for it
// not to.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	relay "github.com/dbhq-uk/heliograph-relay"
)

var version = "dev"

// newServer exists only to carry the build's version into the server, so
// /version reports the binary that is actually answering rather than a
// constant somebody forgot to update.
func newServer(store *relay.Store, auth relay.Authoriser, log *slog.Logger) *relay.Server {
	s := relay.NewAuthorisingServer(store, auth, log)
	s.Version = version
	return s
}

const usage = `heliograph-relay - stores and forwards ciphertext it cannot read

  HELIOGRAPH_RELAY_ADDR        listen address         (default :8080)
  HELIOGRAPH_RELAY_ESTATES     estate:controlToken:stationToken, comma separated
  HELIOGRAPH_RELAY_AUTHORISER  a URL that answers authorisation decisions.
                               When set, estates are that service's business
                               and HELIOGRAPH_RELAY_ESTATES is not read

Example:

  HELIOGRAPH_RELAY_ESTATES=payments:$CTL:$STN heliograph-relay

Generate tokens with something that is actually random:

  head -c 32 /dev/urandom | base64

Behind your own authoriser:

  HELIOGRAPH_RELAY_AUTHORISER=https://authz.example/decide heliograph-relay

It POSTs {credential, estate, station, dir, op, bytes} and expects
{"allow": bool, "reason": string}. Only 200 is a decision: anything else is
treated as the authoriser being unreachable, and the relay answers 503 rather
than 401, so a reader is not sent to check a token when the fault is here.
`

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version":
			fmt.Printf("heliograph-relay %s\n", version)
			return
		default:
			fmt.Print(usage)
			os.Exit(2)
		}
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	spec := os.Getenv("HELIOGRAPH_RELAY_ESTATES")
	authoriser := strings.TrimSpace(os.Getenv("HELIOGRAPH_RELAY_AUTHORISER"))

	if authoriser != "" {
		// Somebody else's directory decides. This is how the hosted service
		// adds tenants, estates, quota and billing without adding a line to the
		// binary in the path, and it is here rather than kept private so that a
		// self-hoster with their own authoriser is not being handed a
		// hollowed-out version of the transport.
		if strings.TrimSpace(spec) != "" {
			log.Warn("HELIOGRAPH_RELAY_ESTATES is set and will not be read, because HELIOGRAPH_RELAY_AUTHORISER is set. Two sources of truth for the same question is a configuration nobody can reason about",
				"authoriser", authoriser)
		}
		serve(relay.NewRemoteAuth(authoriser), log, 0)
		return
	}

	auth := relay.NewStaticAuth()
	if strings.TrimSpace(spec) == "" {
		// Refusing to start beats starting with no estates and answering 401 to
		// everything, which looks exactly like a credential problem at the far
		// end and sends the reader to the wrong side of the gap.
		fmt.Fprint(os.Stderr, "heliograph-relay: neither HELIOGRAPH_RELAY_ESTATES nor HELIOGRAPH_RELAY_AUTHORISER is set, so no client could ever authenticate.\n\n")
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	n := 0
	for _, e := range strings.Split(spec, ",") {
		parts := strings.Split(strings.TrimSpace(e), ":")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			fmt.Fprintf(os.Stderr, "heliograph-relay: %q is not estate:controlToken:stationToken\n", e)
			os.Exit(2)
		}
		if parts[1] == parts[2] {
			// One token for both sides collapses the only scope separation
			// there is, and a station credential could then queue requests.
			fmt.Fprintf(os.Stderr, "heliograph-relay: estate %q uses the same token for both sides, which removes the scope separation entirely\n", parts[0])
			os.Exit(2)
		}
		auth.SetControl(parts[0], parts[1])
		auth.SetStation(parts[0], parts[2])
		// The fingerprint, never the token. An operator has to be able to say
		// which credential is configured without saying what it is.
		log.Info("estate configured", "estate", parts[0],
			"control", relay.FingerprintToken(parts[1]),
			"station", relay.FingerprintToken(parts[2]))
		n++
	}
	serve(relay.FromAuth(auth), log, n)
}

// serve runs the server until a signal, whichever authoriser it was handed.
func serve(auth relay.Authoriser, log *slog.Logger, estates int) {
	store := relay.NewStore()
	go func() {
		for range time.Tick(time.Hour) {
			if dropped := store.Sweep(); dropped > 0 {
				log.Info("expired", "messages", dropped)
			}
		}
	}()

	addr := os.Getenv("HELIOGRAPH_RELAY_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	srv := &http.Server{
		Addr:    addr,
		Handler: newServer(store, auth, log).Routes(),
		// Generous, because a long poll holds the line by design. The read
		// header timeout is the one that matters against a slow-loris.
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Info("listening", "addr", addr, "estates", estates, "version", version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("serve", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
