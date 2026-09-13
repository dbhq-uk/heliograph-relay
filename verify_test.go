package relay

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"net/http/httptest"
	"testing"
	"time"
)

// signing in this file is the CONTROL PLANE's half, written out here because a
// test has to mint a lease to check that verifying one works.
//
// The relay does not do this and provably cannot: TestTheRelayBinaryCannotSignALease
// reads the built binary's symbol table and fails if any route to an ed25519
// private key is linked into it.
func mintedBy(priv ed25519.PrivateKey) func(payload string) string {
	return func(payload string) string { return string(ed25519.Sign(priv, []byte(payload))) }
}

func testKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// A lease signed by the control plane verifies, and the relay needs only the
// public half to check it.
func TestALeaseSignedByTheControlPlaneVerifies(t *testing.T) {
	pub, priv := testKeypair(t)
	auth := &AuthorityAuth{
		Inner:  &refusesEverything{reason: ReasonAuthoriserUnavailable},
		Verify: Ed25519Verifier(pub),
		Now:    time.Now,
	}
	srv := scopedServer(t, auth)

	lease := NewAuthority(Authority{
		Scope:     alphaScope(),
		NotBefore: time.Now().Add(-time.Minute),
		Expires:   time.Now().Add(10 * time.Minute),
	}, mintedBy(priv))

	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", lease, 1, []byte("status")); r.StatusCode != 202 {
		t.Fatalf("a properly signed lease was refused: %d", r.StatusCode)
	}
}

// A lease signed by anybody else does not, which is the whole point of moving
// from a stub to a real primitive.
func TestALeaseSignedByTheWrongKeyIsRefused(t *testing.T) {
	pub, _ := testKeypair(t)
	_, attacker := testKeypair(t)
	auth := &AuthorityAuth{
		Inner:  &refusesEverything{reason: ReasonBadCredential},
		Verify: Ed25519Verifier(pub),
		Now:    time.Now,
	}
	srv := scopedServer(t, auth)

	forged := NewAuthority(Authority{
		Scope:     Scope{Estate: "e-9f3c1a", AllStations: true, Read: []string{"c2s", "s2c"}, Write: []string{"c2s", "s2c"}},
		NotBefore: time.Now().Add(-time.Minute),
		Expires:   time.Now().Add(10 * time.Minute),
	}, mintedBy(attacker))

	r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", forged, 1, []byte("x"))
	if r.StatusCode == 202 {
		t.Fatal("a lease signed by a key this relay does not trust was accepted")
	}
	if got := reasonOf(t, r); got != string(ReasonAuthorityUnverifiable) {
		t.Errorf("refused as %q, want %q", got, ReasonAuthorityUnverifiable)
	}
}

// Widening a lease after it was signed breaks the signature, because the
// signature covers the encoded payload rather than the decoded fields.
func TestWideningASignedLeaseBreaksIt(t *testing.T) {
	pub, priv := testKeypair(t)
	auth := &AuthorityAuth{
		Inner:  &refusesEverything{reason: ReasonBadCredential},
		Verify: Ed25519Verifier(pub),
		Now:    time.Now,
	}
	srv := scopedServer(t, auth)

	honest := NewAuthority(Authority{
		Scope:     alphaScope(),
		NotBefore: time.Now().Add(-time.Minute),
		Expires:   time.Now().Add(10 * time.Minute),
	}, mintedBy(priv))
	// The same signature, carried across to a payload it was not made for.
	sig := signatureOf(t, honest)
	wider := NewAuthority(Authority{
		Scope:     Scope{Estate: "e-9f3c1a", AllStations: true, Read: []string{"c2s", "s2c"}, Write: []string{"c2s", "s2c"}},
		NotBefore: time.Now().Add(-time.Minute),
		Expires:   time.Now().Add(10 * time.Minute),
	}, func(string) string { return sig })

	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/c2s", wider, 1, []byte("x")); r.StatusCode == 202 {
		t.Fatal("a lease widened after signing was accepted")
	}
}

func signatureOf(t *testing.T, lease string) string {
	t.Helper()
	_, s, err := ParseAuthority(lease)
	if err != nil {
		t.Fatal(err)
	}
	return s.signature
}

// A verifier built from a key that is not an Ed25519 public key refuses
// everything, rather than refusing nothing.
func TestAVerifierWithNoUsableKeyRefusesEverything(t *testing.T) {
	for name, key := range map[string][]byte{
		"empty":     nil,
		"too short": make([]byte, 16),
		"too long":  make([]byte, 64),
	} {
		v := Ed25519Verifier(key)
		if v.Verify("anything", "anything") {
			t.Errorf("a verifier built from a %s key verified something", name)
		}
	}
}

// The public key is read from configuration, in either of the two spellings an
// operator is likely to have it in, and a key that is neither is refused by
// name rather than ignored.
func TestThePublicKeyIsReadFromConfiguration(t *testing.T) {
	pub, _ := testKeypair(t)
	for name, spelling := range map[string]string{
		"hex":                 hex.EncodeToString(pub),
		"base64":              base64.StdEncoding.EncodeToString(pub),
		"base64url, unpadded": base64.RawURLEncoding.EncodeToString(pub),
	} {
		got, err := ParseEd25519PublicKey(spelling)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !got.Equal(pub) {
			t.Errorf("%s: the key round-tripped to something else", name)
		}
	}
	for _, bad := range []string{"", "not-a-key", "deadbeef", hex.EncodeToString(make([]byte, 31))} {
		if _, err := ParseEd25519PublicKey(bad); err == nil {
			t.Errorf("%q was accepted as a public key", bad)
		}
	}
}

// A private key offered where a public key belongs is refused.
//
// An Ed25519 private key is 64 bytes and its last 32 are the public half, so
// somebody pasting the wrong half of a keypair into configuration is an easy
// mistake with a bad outcome: the relay would hold signing material. Refused by
// length, and named, so the mistake is visible rather than silently truncated.
func TestAPrivateKeyIsRefusedWhereAPublicKeyBelongs(t *testing.T) {
	_, priv := testKeypair(t)
	if _, err := ParseEd25519PublicKey(hex.EncodeToString(priv)); err == nil {
		t.Fatal("a 64-byte private key was accepted as a public key")
	}
}

// And the lease still needs everything else to be right. A real signature does
// not excuse an expired lease, a revoked epoch or a scope that does not reach.
func TestASignedLeaseStillHasToBeInScopeAndInDate(t *testing.T) {
	pub, priv := testKeypair(t)
	auth := &AuthorityAuth{
		Inner:  &refusesEverything{reason: ReasonBadCredential},
		Verify: Ed25519Verifier(pub),
		Now:    time.Now,
	}
	srv := scopedServer(t, auth)

	expired := NewAuthority(Authority{
		Scope:     alphaScope(),
		NotBefore: time.Now().Add(-20 * time.Minute),
		Expires:   time.Now().Add(-10 * time.Minute),
	}, mintedBy(priv))
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", expired, 1, []byte("x")); r.StatusCode == 202 {
		t.Error("a signed but expired lease was accepted")
	}

	live := NewAuthority(Authority{
		Scope:     alphaScope(),
		NotBefore: time.Now().Add(-time.Minute),
		Expires:   time.Now().Add(10 * time.Minute),
	}, mintedBy(priv))
	if r := put(t, srv, "/v1/e-2b7d44/till-07/s2c", live, 1, []byte("x")); r.StatusCode == 202 {
		t.Error("a signed lease reached another customer's queue")
	}
}

// The relay still validates a signed lease with no network call. This is the
// property the whole design rests on and the signature must not have cost it.
func TestASignedLeaseIsStillValidatedWithNoNetworkCall(t *testing.T) {
	pub, priv := testKeypair(t)
	down := &refusesEverything{reason: ReasonAuthoriserUnavailable}
	auth := &AuthorityAuth{Inner: down, Verify: Ed25519Verifier(pub), Now: time.Now}
	srv := httptest.NewServer(NewAuthorisingServer(NewStore(), auth, quiet()).Routes())
	t.Cleanup(srv.Close)

	lease := NewAuthority(Authority{
		Scope:     alphaScope(),
		NotBefore: time.Now().Add(-time.Minute),
		Expires:   time.Now().Add(10 * time.Minute),
	}, mintedBy(priv))

	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", lease, 1, []byte("x")); r.StatusCode != 202 {
		t.Fatalf("got %d", r.StatusCode)
	}
	if n := down.timesAsked(); n != 0 {
		t.Errorf("the relay consulted the authoriser %d times to verify a lease it was handed", n)
	}
}
