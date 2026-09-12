// Package conformance is the executable form of the relay contract.
//
// There are two implementations of this server: the Go one in this repository,
// and the Cloudflare Worker in edge/. That is a deliberate second
// implementation, taken on because the shapes genuinely differ - a Durable
// Object is how you hold state at the edge, and a Go binary is how you run this
// anywhere else - and the cost of it is drift.
//
// Drift is only dangerous when it is untested. So the contract lives here,
// asserted over HTTP against a base URL, and both implementations run it. The
// same reasoning, and the same shape, as the capture conformance suite in
// heliograph-skill: one specification, several implementations, and an
// unproven implementation is not permitted.
//
// Nothing in this package may import the Go server. The moment it does it
// stops being a specification and becomes a second copy of one implementation.
//
// # What this suite cannot assert, and it is not a gap that can be closed here
//
// Every assertion is made over HTTP, so it can only reach what a client can
// reach. A STORAGE MODEL is not one of those things. A relay that holds a
// message in memory and a relay that writes it to disk answer every request
// below identically, so nothing here can tell them apart.
//
// That is not hypothetical. The two implementations diverged on exactly this -
// the Worker persisted every message to Durable Object storage while the README
// said neither did - and both passed this suite the whole time
// (heliograph-io/heliograph-cloud#47).
//
// So storage claims are NOT conformance-enforced and must not be assumed
// covered because this suite is green. Each implementation asserts its own, in
// its own tests, with access this suite does not have:
//
//	storage_test.go                    the Go server
//	edge/test/storage-model.test.ts    the Worker, reading Durable Object storage
//
// Report says so on every run, so a green result does not read as broader than
// it is.
package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Target is a running relay and the credentials to talk to it.
type Target struct {
	BaseURL    string
	Estate     string
	Station    string
	Control    string // the control token
	StationTok string // the station token
	// OtherEstate and its control token, for the isolation checks. A relay
	// with one estate configured cannot prove it keeps two apart.
	OtherEstate  string
	OtherControl string
	Client       *http.Client
}

// Result is one assertion.
type Result struct {
	Name string
	OK   bool
	Why  string
}

func (t Target) client() *http.Client {
	if t.Client != nil {
		return t.Client
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (t Target) url(estate, station, dir, q string) string {
	u := fmt.Sprintf("%s/v1/%s/%s/%s", strings.TrimRight(t.BaseURL, "/"), estate, station, dir)
	if q != "" {
		u += "?" + q
	}
	return u
}

func (t Target) do(method, url, tok string, body []byte) (*http.Response, []byte, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		return nil, nil, err
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client().Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b, nil
}

func (t Target) put(estate, station, dir, tok string, seq uint64, body []byte) (int, error) {
	payload, _ := json.Marshal(map[string]any{"seq": seq, "body": body})
	resp, _, err := t.do("POST", t.url(estate, station, dir, ""), tok, payload)
	if err != nil {
		return 0, err
	}
	return resp.StatusCode, nil
}

type msg struct {
	Seq  uint64 `json:"seq"`
	Body []byte `json:"body"`
}

func (t Target) take(estate, station, dir, tok string) (int, []msg, error) {
	resp, b, err := t.do("GET", t.url(estate, station, dir, "wait=0"), tok, nil)
	if err != nil {
		return 0, nil, err
	}
	var out []msg
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out, nil
}

// Run executes every assertion and returns them in order.
//
// It uses a fresh station name per run, so a suite run twice against the same
// relay does not read its own leftovers and report a pass it did not earn.
func Run(t Target) []Result {
	var out []Result
	ok := func(name string, cond bool, why string) {
		out = append(out, Result{Name: name, OK: cond, Why: why})
	}
	uniq := fmt.Sprintf("%s-%d", t.Station, time.Now().UnixNano())

	// --- health ---------------------------------------------------------
	resp, _, err := t.do("GET", strings.TrimRight(t.BaseURL, "/")+"/health", "", nil)
	ok("health answers without a token", err == nil && resp != nil && resp.StatusCode == 200,
		fmt.Sprintf("err=%v", err))

	// --- identity, and the two endpoints a human reaches for -------------
	// Both are unauthenticated on purpose. "The relay you are talking to is
	// the relay you read" is not checkable if you need a credential to ask
	// which relay it is, and the answer reveals nothing a reader of the
	// public source does not already have.
	base := strings.TrimRight(t.BaseURL, "/")
	for _, path := range []string{"/", "/version"} {
		resp, body, err := t.do("GET", base+path, "", nil)
		got := struct {
			Service        string `json:"service"`
			Implementation string `json:"implementation"`
			Version        string `json:"version"`
			Source         string `json:"source"`
		}{}
		parsed := err == nil && json.Unmarshal(body, &got) == nil
		ok(path+" answers without a token", err == nil && resp != nil && resp.StatusCode == 200,
			fmt.Sprintf("err=%v", err))
		ok(path+" names the service and the implementation",
			parsed && got.Service == "heliograph-relay" && got.Implementation != "",
			fmt.Sprintf("service=%q implementation=%q", got.Service, got.Implementation))
		// Never blank. A build nobody stamped must say "unknown" rather than
		// return an empty string, because a blank field reads as a broken
		// client where "unknown" is a true answer somebody can act on.
		ok(path+" reports a version that is never blank", parsed && got.Version != "",
			fmt.Sprintf("version=%q", got.Version))
		ok(path+" points at the source", parsed && got.Source != "",
			fmt.Sprintf("source=%q", got.Source))
	}

	// A browser must get a page, not a download. / used to answer
	// {"error":"no such route"} with a JSON content type, and mobile Safari
	// offered that as a 25-byte file rather than showing it - which is what
	// somebody who pasted the hostname into a phone actually got.
	{
		req, _ := http.NewRequest("GET", base+"/", nil)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
		resp, err := t.client().Do(req)
		ct := ""
		if resp != nil {
			ct = resp.Header.Get("Content-Type")
			_ = resp.Body.Close()
		}
		ok("/ gives a browser HTML rather than a file to download",
			err == nil && strings.HasPrefix(ct, "text/html"),
			fmt.Sprintf("content-type=%q err=%v", ct, err))
	}

	// --- a message goes in and comes back unchanged ----------------------
	// Bytes that are not valid UTF-8 and not valid JSON, because the body is
	// ciphertext and the relay must never interpret it.
	want := []byte{0x00, 0xff, 0x7b, 0x22, 0x10, 'c', 'i', 'p', 'h', 'e', 'r', 0xfe}
	code, err := t.put(t.Estate, uniq, "c2s", t.Control, 1, want)
	ok("a control token may queue a request", code == 202, fmt.Sprintf("got %d %v", code, err))

	code, got, err := t.take(t.Estate, uniq, "c2s", t.StationTok)
	ok("a station token may collect it", code == 200, fmt.Sprintf("got %d %v", code, err))
	ok("exactly one message came back", len(got) == 1, fmt.Sprintf("got %d", len(got)))
	if len(got) == 1 {
		ok("the body is byte-for-byte what was sent", bytes.Equal(got[0].Body, want),
			fmt.Sprintf("got %v", got[0].Body))
		ok("the sequence number is unchanged", got[0].Seq == 1,
			fmt.Sprintf("got %d", got[0].Seq))
	}

	// --- collecting removes it ------------------------------------------
	_, got, _ = t.take(t.Estate, uniq, "c2s", t.StationTok)
	ok("a collected message is not delivered twice", len(got) == 0, fmt.Sprintf("got %d", len(got)))

	// --- the scope split, which is the one that matters ------------------
	// A station credential sits on a machine nobody can reach and cannot be
	// rotated quickly. It must not be able to queue a request.
	code, _ = t.put(t.Estate, uniq, "c2s", t.StationTok, 2, []byte("evil"))
	ok("a station token may NOT queue a request", code != 202, fmt.Sprintf("got %d", code))

	code, _ = t.put(t.Estate, uniq, "s2c", t.Control, 2, []byte("fake status"))
	ok("a control token may NOT publish a status", code != 202, fmt.Sprintf("got %d", code))

	code, _ = t.put(t.Estate, uniq, "s2c", t.StationTok, 1, []byte("real status"))
	ok("a station token may publish a status", code == 202, fmt.Sprintf("got %d", code))

	code, got, _ = t.take(t.Estate, uniq, "s2c", t.Control)
	ok("a control token may read a status", code == 200 && len(got) == 1,
		fmt.Sprintf("got %d, %d messages", code, len(got)))

	// --- no credential ---------------------------------------------------
	code, _ = t.put(t.Estate, uniq, "c2s", "", 3, []byte("x"))
	ok("a put with no token is refused", code == 401, fmt.Sprintf("got %d", code))
	code, _, _ = t.take(t.Estate, uniq, "c2s", "")
	ok("a get with no token is refused", code == 401, fmt.Sprintf("got %d", code))

	code, _ = t.put(t.Estate, uniq, "c2s", "definitely-not-the-token", 3, []byte("x"))
	ok("a put with a wrong token is refused", code == 401, fmt.Sprintf("got %d", code))

	// --- estates are isolated --------------------------------------------
	if t.OtherEstate != "" {
		code, _ = t.put(t.OtherEstate, uniq, "c2s", t.Control, 1, []byte("x"))
		ok("one estate's token cannot write into another", code != 202, fmt.Sprintf("got %d", code))
		code, _, _ = t.take(t.OtherEstate, uniq, "c2s", t.StationTok)
		ok("one estate's token cannot read another", code == 401, fmt.Sprintf("got %d", code))
	}

	// --- an estate that was never configured ------------------------------
	// The zero value of a hash must not match. That would authorise everybody.
	code, _ = t.put("estate-that-does-not-exist", uniq, "c2s", t.Control, 1, []byte("x"))
	ok("an unconfigured estate is refused", code != 202, fmt.Sprintf("got %d", code))

	// --- a direction that is not one --------------------------------------
	code, _ = t.put(t.Estate, uniq, "sideways", t.Control, 1, []byte("x"))
	ok("a direction other than c2s or s2c is refused", code != 202, fmt.Sprintf("got %d", code))

	// --- the body is never interpreted -------------------------------------
	// If the relay ever started refusing bodies for their shape, it would be
	// reading them.
	allOK := true
	for i, body := range [][]byte{{}, {0}, []byte("{not json"), bytes.Repeat([]byte{0xff}, 4096)} {
		c, _ := t.put(t.Estate, fmt.Sprintf("%s-body%d", uniq, i), "c2s", t.Control, 1, body)
		if c != 202 {
			allOK = false
		}
	}
	ok("any body is accepted, including one that is not JSON or UTF-8", allOK, "")

	// --- ordering is the recipient's job -----------------------------------
	// Seq is carried but never enforced here: it is signed end to end, and a
	// hostile relay cannot lie about it. Enforcing it here would look like a
	// safety feature and be worth nothing.
	seqStation := uniq + "-seq"
	_, _ = t.put(t.Estate, seqStation, "c2s", t.Control, 99, []byte("a"))
	_, _ = t.put(t.Estate, seqStation, "c2s", t.Control, 1, []byte("b"))
	_, got, _ = t.take(t.Estate, seqStation, "c2s", t.StationTok)
	carried := len(got) == 2
	if carried {
		sort.Slice(got, func(a, b int) bool { return got[a].Seq < got[b].Seq })
		carried = got[0].Seq == 1 && got[1].Seq == 99
	}
	ok("sequence numbers are carried, not rewritten", carried, fmt.Sprintf("got %+v", got))

	// --- the long poll ------------------------------------------------------
	pollStation := uniq + "-poll"
	done := make(chan int, 1)
	go func() {
		resp, b, err := t.do("GET", t.url(t.Estate, pollStation, "c2s", ""), t.StationTok, nil)
		if err != nil || resp.StatusCode != 200 {
			done <- -1
			return
		}
		var m []msg
		_ = json.Unmarshal(b, &m)
		done <- len(m)
	}()
	time.Sleep(400 * time.Millisecond)
	_, _ = t.put(t.Estate, pollStation, "c2s", t.Control, 1, []byte("wake up"))
	select {
	case n := <-done:
		ok("a long poll wakes when a message arrives", n == 1, fmt.Sprintf("woke with %d", n))
	case <-time.After(40 * time.Second):
		ok("a long poll wakes when a message arrives", false, "it never returned")
	}

	// --- wait=0 returns immediately ------------------------------------------
	start := time.Now()
	_, _, _ = t.take(t.Estate, uniq+"-empty", "c2s", t.StationTok)
	ok("wait=0 returns immediately rather than holding the line",
		time.Since(start) < 5*time.Second, time.Since(start).String())

	return out
}

// Report renders results, and says whether everything passed.
func Report(w io.Writer, name string, rs []Result) bool {
	fmt.Fprintf(w, "\n--- relay conformance: %s ---\n", name)
	pass, fail := 0, 0
	for _, r := range rs {
		if r.OK {
			pass++
			fmt.Fprintf(w, "ok   %s\n", r.Name)
		} else {
			fail++
			fmt.Fprintf(w, "FAIL %s\n", r.Name)
			if r.Why != "" {
				fmt.Fprintf(w, "     %s\n", r.Why)
			}
		}
	}
	fmt.Fprintf(w, "\n%s: %d passed, %d failed\n", name, pass, fail)
	// Printed on every run, pass or fail. A green suite would otherwise read as
	// "the relay is correct" when what it means is "the relay behaves correctly
	// over HTTP", and the difference is where the two implementations diverged.
	fmt.Fprintf(w, "not asserted here: the storage model, which is not observable over HTTP.\n"+
		"  See storage_test.go and edge/test/storage-model.test.ts.\n")
	return fail == 0
}
