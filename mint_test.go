package relay_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The relay cannot mint a lease, and this establishes it by construction rather
// than by reading the source.
//
// This is the assertion that carries the whole decision on
// heliograph-io/heliograph-cloud#75. Ed25519 is permitted here for VERIFICATION
// ONLY, and the reason that keeps the product's claim true is that a public key
// is not a secret: there is still no key in this relay worth stealing. The
// moment a signing path is reachable, that stops being so, and it stops
// silently.
//
// A grep would not settle it. Somebody can import a package and not call it,
// or call it behind a flag nobody sets. The linker is the honest witness: Go
// links only what is reachable, so if the binary has no way to CONSTRUCT an
// ed25519 private key, no code path in it can sign anything.
//
// Note what is deliberately NOT in the list. `fips140/ed25519.signWithDom` is
// present in a verify-only binary, because the FIPS module keeps it beside the
// verification it does use. It is unreachable without a private key, and every
// route to one is what this test forbids.
//
// WHAT THIS CHECKS IS THE BINARY, NOT THE PACKAGE, and the difference is worth
// knowing because it was found by breaking the guard and watching it NOT fire.
// An exported signing helper added to this package and called by nobody is
// dropped by the linker, so the binary still cannot sign and this test still
// passes - correctly, because the claim is about the artefact an operator runs
// and hashes. A signing path reachable from main is caught, which is the change
// that would actually ship one.
//
// The consequence: somebody importing this package as a library could sign. The
// claim has never covered that, and `cmd/heliograph-relay` is what the README
// tells people to build.
func TestTheRelayBinaryCannotSignALease(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "heliograph-relay")
	build := exec.Command("go", "build", "-o", bin, "./cmd/heliograph-relay")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	assertCannotSign(t, bin, "the relay binary")
}

// The conformance harness is allowed to sign, and does. It is a test tool and
// is never deployed, so asserting the same thing about it would be asserting
// the wrong thing - but checking that this test can TELL THE DIFFERENCE is the
// only way to know the check works at all.
//
// This is the guard broken on purpose, permanently, rather than once by hand.
func TestTheSigningCheckCanTellASignerFromAVerifier(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "conformance")
	build := exec.Command("go", "build", "-o", bin, "./cmd/conformance")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	found := signingSymbols(t, bin)
	if len(found) == 0 {
		t.Fatal("the conformance harness signs leases, so this check found nothing and proves nothing about the relay either")
	}
	t.Logf("the harness links %d signing symbol(s), so the check discriminates: %s",
		len(found), strings.Join(found, ", "))
}

// signingSymbolPrefixes are the routes to an ed25519 private key.
//
// Verified in both directions rather than assumed: a binary that calls only
// ed25519.Verify links none of these, and one that calls GenerateKey and Sign
// links all of them.
var signingSymbolPrefixes = []string{
	"crypto/ed25519.GenerateKey",
	"crypto/ed25519.sign",
	"crypto/ed25519.newKeyFromSeed",
	"crypto/internal/fips140/ed25519.generateKey",
	"crypto/internal/fips140/ed25519.newPrivateKey",
	"crypto/internal/fips140/ed25519.newPrivateKeyFromSeed",
}

func signingSymbols(t *testing.T, bin string) []string {
	t.Helper()
	out, err := exec.Command("go", "tool", "nm", bin).Output()
	if err != nil {
		t.Fatalf("go tool nm %s: %v", bin, err)
	}
	var found []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[len(fields)-1]
		for _, p := range signingSymbolPrefixes {
			if strings.HasPrefix(name, p) {
				found = append(found, name)
			}
		}
	}
	return found
}

func assertCannotSign(t *testing.T, bin, what string) {
	t.Helper()
	if found := signingSymbols(t, bin); len(found) > 0 {
		t.Fatalf("%s links a route to an ed25519 private key, so it can mint leases: %s",
			what, strings.Join(found, ", "))
	}
	// And it does verify, or the check above is satisfied by a binary that
	// simply does not do Ed25519 at all, which would prove nothing.
	out, err := exec.Command("go", "tool", "nm", bin).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "crypto/internal/fips140/ed25519.verify") {
		t.Fatalf("%s links no ed25519 verification, so the absence of signing proves nothing", what)
	}
}

// The Worker is held to the same rule by its own CI step, because a bundle has
// no symbol table to read. This test fails if that step is ever removed, so the
// two implementations cannot quietly diverge on the one rule that matters most.
func TestTheWorkerIsHeldToTheSameSigningRule(t *testing.T) {
	wf, err := os.ReadFile(".github/workflows/validate.yml")
	if err != nil {
		t.Fatal(err)
	}
	// Matched against what the workflow actually contains, which is an escaped
	// regex rather than the bare call names. The first version of this test
	// looked for "subtle.sign" and failed against a workflow that forbids it
	// correctly, which is the wrong way round for a guard.
	for _, want := range []string{
		`subtle\.(sign|generateKey`,
		"crypto.subtle.importKey",
		"crypto.subtle.verify",
		"verification only at the edge",
	} {
		if !strings.Contains(string(wf), want) {
			t.Errorf("validate.yml no longer mentions %q, so the edge signing rule may have been dropped", want)
		}
	}
}
