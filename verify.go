package relay

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Ed25519, for verification only.
//
// THIS FILE IS THE ONE NARROWING OF A PUBLISHED CLAIM IN THIS REPOSITORY, so it
// says plainly what changed and what did not.
//
// What this repository used to say, in README.md, SECURITY.md and relay.go's
// package comment, was "there is no cryptography in this repository". That was
// a PROXY for the claim that actually matters, which is that there is no key
// here worth stealing and no plaintext to subpoena. The proxy is what has
// narrowed. The claim itself is untouched, because a public key is not a
// secret: an attacker who takes everything this relay holds gets a key that
// checks signatures and makes none.
//
// WHY IT HAD TO NARROW. An authorisation lease is minted by a control plane and
// handed to a relay that has never seen it before, so honouring one means
// checking a signature. Without that, a relay either trusts an unsigned lease,
// which means trusting a forged one, or refuses every lease - and refusing every
// lease removes the control-plane outage protection that
// heliograph-io/heliograph-cloud#75 exists to provide, on the hosted relay
// almost every customer touches. The feature would have been theatre.
//
// WHAT WAS REJECTED. HMAC-SHA256 could have been built from crypto/sha256 alone
// and would have passed the old rule as written. It is symmetric, so a relay
// able to verify is a relay able to MINT any lease it likes, and that ends the
// claim rather than narrowing the proxy.
//
// HOW THE NARROWING IS HELD IN PLACE. Not by this comment, and not by a grep.
// TestTheRelayBinaryCannotSignALease builds cmd/heliograph-relay and reads its
// symbol table: the Go linker includes only reachable code, so a binary with no
// route to constructing an ed25519 private key has no code path that could sign
// anything. TestTheSigningCheckCanTellASignerFromAVerifier builds the
// conformance harness, which does sign, and fails if the check cannot see the
// difference.

// Ed25519Verifier checks lease signatures against one public key.
//
// It verifies and does nothing else. There is no constructor here that produces
// a private key, no key generation, and no signing, and that is enforced by the
// linker rather than by intention.
//
// A key that is not a usable Ed25519 public key produces a verifier that
// refuses everything. Failing closed is the only safe direction: a verifier
// that accepted everything because its key was misconfigured would accept a
// forged lease, and the forger chooses the scope.
func Ed25519Verifier(pub ed25519.PublicKey) AuthorityVerifier {
	if len(pub) != ed25519.PublicKeySize {
		return VerifierFunc(func(string, string) bool { return false })
	}
	// Copied, so a caller that reuses its buffer cannot change what this relay
	// trusts after the fact.
	key := make(ed25519.PublicKey, len(pub))
	copy(key, pub)
	return VerifierFunc(func(payload, signature string) bool {
		if len(signature) != ed25519.SignatureSize {
			return false
		}
		return ed25519.Verify(key, []byte(payload), []byte(signature))
	})
}

// ParseEd25519PublicKey reads a public key from configuration.
//
// Hex, standard base64 or unpadded base64url, because an operator will have it
// in whichever spelling whatever generated it produced, and refusing the other
// two buys nothing. Anything else is an error naming the problem rather than a
// verifier that silently refuses every lease, which is the same symptom as a
// control plane signing with the wrong key and would send somebody looking in
// the wrong place.
func ParseEd25519PublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("no lease verification key configured")
	}
	var raw []byte
	var err error
	switch {
	case len(s) == ed25519.PublicKeySize*2 && isHex(s):
		raw, err = hex.DecodeString(s)
	default:
		raw, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			raw, err = base64.RawURLEncoding.DecodeString(s)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("a lease verification key must be hex or base64: %w", err)
	}
	// An Ed25519 private key is 64 bytes and its last 32 ARE the public half, so
	// a truncating parser would accept one and leave signing material in the
	// relay's configuration. Named and refused instead, because somebody pasting
	// the wrong half of a keypair is an easy mistake with a bad outcome.
	if len(raw) == ed25519.PrivateKeySize {
		return nil, fmt.Errorf("that is a %d-byte Ed25519 PRIVATE key, and this relay wants the %d-byte public half. It never needs a private key and must not be given one",
			ed25519.PrivateKeySize, ed25519.PublicKeySize)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("an Ed25519 public key is %d bytes, and that is %d",
			ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func isHex(s string) bool {
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
