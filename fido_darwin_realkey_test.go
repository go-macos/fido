// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package fido

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	authn "github.com/go-authn/fido"
)

// TestRealKeyHMACSecretAndUV is the test of hmac-secret, credProtect and
// built-in user verification against a REAL authenticator. It runs only with
//
//	FIDO_REAL=1 go test -run TestRealKeyHMACSecretAndUV -v
//
// because it needs a person: a key with a fingerprint sensor (a YubiKey Bio) and
// a finger enrolled on it. Each time the key must verify the person this prints
// one line, "Touch the YubiKey fingerprint sensor now (30 s)", and waits that
// long. A wait that runs out is reported as NOT RUN, not as a failure: nobody
// being there says nothing about the code.
//
// It checks the two traps that make a disk unlock silently wrong:
//
//   - hmac-secret gives a DIFFERENT secret with and without user verification;
//   - under credProtect 3 a probe made before verification is answered "no
//     credentials" by the right key.
//
// and that the secret is stable across two assertions with the same salt. It
// logs lengths and equalities, never a secret.
func TestRealKeyHMACSecretAndUV(t *testing.T) {
	if os.Getenv("FIDO_REAL") != "1" {
		t.Skip("NOT RUN: set FIDO_REAL=1 with a fingerprint key attached")
	}
	const rp = "go-macos-fido-realtest.invalid"
	cdh := sha256.Sum256([]byte("go-macos/fido real key test"))
	salt := sha256.Sum256([]byte("salt one"))

	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	k, err := Open(ctx)
	stop()
	if err != nil {
		t.Skipf("NOT RUN: no key to open: %v", err)
	}
	defer k.Close()

	long, stopLong := context.WithTimeout(context.Background(), 10*time.Second)
	info, err := k.GetInfo(long)
	stopLong()
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	t.Logf("authenticator: %s; extensions %v; PIN protocols %v", info, info.Extensions, info.PINProtocols)
	for _, want := range []string{"hmac-secret", "credProtect"} {
		if !contains(info.Extensions, want) {
			t.Skipf("NOT RUN: this authenticator does not list the %s extension", want)
		}
	}
	if !info.Has("uv") || !info.Has("pinUvAuthToken") {
		t.Skip("NOT RUN: this authenticator has no enrolled built-in user verification (options uv, pinUvAuthToken)")
	}
	proto := authn.PINProtocolOne
	for _, p := range info.PINProtocols {
		if p == uint(authn.PINProtocolTwo) {
			proto = authn.PINProtocolTwo
		}
	}
	t.Logf("using %s", proto)

	step := 0
	// finger runs f with a 30 s bound, after the one line a person reads.
	finger := func(what string, f func(ctx context.Context) error) error {
		step++
		fmt.Fprintf(os.Stderr, "\n[step %d] %s\nTouch the YubiKey fingerprint sensor now (30 s)\n", step, what)
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return f(c)
	}
	notRun := func(err error) {
		if errors.Is(err, context.DeadlineExceeded) {
			t.Skipf("NOT RUN: nobody touched the sensor in time at step %d (%v)", step, err)
		}
	}
	uvToken := func(what string, perms authn.Permissions) authn.Token {
		t.Helper()
		var tok authn.Token
		err := finger(what, func(c context.Context) (err error) {
			tok, err = k.UVToken(c, proto, perms, rp)
			return err
		})
		notRun(err)
		if err != nil {
			t.Fatalf("UVToken for %s: %v", what, err)
		}
		return tok
	}
	register := func(what string, ext authn.Extensions) *authn.Attestation {
		t.Helper()
		tok := uvToken("verify to register: "+what, authn.PermMakeCredential)
		var att *authn.Attestation
		err := finger("confirm the registration: "+what, func(c context.Context) (err error) {
			att, err = k.MakeCredential(c, authn.MakeCredentialRequest{
				ClientDataHash: cdh[:],
				RP:             authn.RelyingParty{ID: rp, Name: "go-macos/fido real key test"},
				User:           authn.User{ID: []byte("realtest-" + what)},
				Token:          tok,
				Extensions:     ext,
			})
			return err
		})
		notRun(err)
		if err != nil {
			t.Fatalf("MakeCredential %s: %v", what, err)
		}
		if !att.Parsed.Flags.Has(authn.FlagUV) {
			t.Errorf("%s: the registration was not verified", what)
		}
		t.Logf("%s: credential %d bytes, hmac-secret=%v credProtect=%d", what,
			len(att.Parsed.CredentialID), att.Extensions.HMACSecret, att.Extensions.CredProtect)
		if !att.Extensions.HMACSecret {
			t.Fatalf("%s: the key did not create the hmac-secret extension", what)
		}
		return att
	}
	assert := func(id []byte, tok authn.Token, h *authn.HMACSecret, opts map[string]bool) (*authn.Assertion, error) {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return k.GetAssertion(c, authn.GetAssertionRequest{
			RPID: rp, ClientDataHash: cdh[:], Allow: []authn.Credential{{ID: id}},
			Token: tok, HMACSecret: h, Options: opts,
		})
	}

	// Credential A: credProtect 3, the policy a disk unlock wants.
	a := register("credProtect 3", authn.Extensions{HMACSecret: true, CredProtect: authn.CredProtectRequired})
	if a.Extensions.CredProtect != authn.CredProtectRequired {
		t.Errorf("asked for credProtect 3, the key applied %d", a.Extensions.CredProtect)
	}

	// Trap 2: the probe BEFORE verification. "up": false so that it asks for no
	// touch: it is only a question, and the right key must answer "none".
	_, err = assert(a.Parsed.CredentialID, authn.Token{}, nil, map[string]bool{"up": false})
	if err == nil || !strings.Contains(err.Error(), "no credential") {
		t.Errorf("trap 2: an unverified probe of a credProtect 3 credential gave %v, wanted \"no credential\"", err)
	} else {
		t.Logf("trap 2 confirmed: an unverified probe of the right credential id is answered %q", "no credential")
	}

	// Verification FIRST, then the probe and the secret; twice, with a new token
	// each time because a getAssertion permission is spent by use.
	var first, second []byte
	for i := 0; i < 2; i++ {
		tok := uvToken(fmt.Sprintf("verify to unlock (%d of 2)", i+1), authn.PermGetAssertion)
		var out *authn.Assertion
		err := finger("confirm the assertion", func(context.Context) (err error) {
			out, err = assert(a.Parsed.CredentialID, tok, &authn.HMACSecret{Protocol: proto, Salt1: salt[:], RequireUV: true}, nil)
			return err
		})
		notRun(err)
		if err != nil {
			t.Fatalf("assertion %d after verification: %v", i+1, err)
		}
		if !out.Parsed.Flags.Has(authn.FlagUV) || len(out.HMACSecret.First) != 32 {
			t.Fatalf("assertion %d: UV=%v, secret %d bytes", i+1, out.Parsed.Flags.Has(authn.FlagUV), len(out.HMACSecret.First))
		}
		if i == 0 {
			first = out.HMACSecret.First
		} else {
			second = out.HMACSecret.First
		}
	}
	t.Logf("verified secret: %d bytes, stable across two assertions: %v", len(first), bytes.Equal(first, second))
	if !bytes.Equal(first, second) {
		t.Error("the hmac-secret output changed between two assertions with the same salt")
	}

	// Credential B, default policy, so that an UNVERIFIED request is answered:
	// trap 1, the secret without verification is another secret.
	b := register("default policy", authn.Extensions{HMACSecret: true})
	var plain *authn.Assertion
	err = finger("unverified assertion (presence only)", func(context.Context) (err error) {
		plain, err = assert(b.Parsed.CredentialID, authn.Token{}, &authn.HMACSecret{Protocol: proto, Salt1: salt[:]}, nil)
		return err
	})
	notRun(err)
	if err != nil {
		t.Logf("trap 1 NOT CHECKED: the key refuses an unverified assertion (%v)", err)
	} else {
		tok := uvToken("verify to unlock", authn.PermGetAssertion)
		var verified *authn.Assertion
		err := finger("confirm the verified assertion", func(context.Context) (err error) {
			verified, err = assert(b.Parsed.CredentialID, tok, &authn.HMACSecret{Protocol: proto, Salt1: salt[:], RequireUV: true}, nil)
			return err
		})
		notRun(err)
		if err != nil {
			t.Fatalf("verified assertion: %v", err)
		}
		t.Logf("trap 1: unverified request UV=%v, verified request UV=%v, secrets equal: %v",
			plain.Parsed.Flags.Has(authn.FlagUV), verified.Parsed.Flags.Has(authn.FlagUV),
			bytes.Equal(plain.HMACSecret.First, verified.HMACSecret.First))
		if plain.Parsed.Flags.Has(authn.FlagUV) {
			t.Log("the unverified request was verified by the key itself (the touch matched a finger), so the two secrets are the same kind")
		} else if bytes.Equal(plain.HMACSecret.First, verified.HMACSecret.First) {
			t.Error("trap 1: verified and unverified requests gave the SAME secret")
		}
		// RequireUV refuses to hand over the unverified one.
		if !plain.Parsed.Flags.Has(authn.FlagUV) {
			s := &authn.HMACSecret{Protocol: proto, Salt1: salt[:], RequireUV: true}
			_ = finger("unverified assertion with RequireUV", func(context.Context) error {
				got, err := assert(b.Parsed.CredentialID, authn.Token{}, s, nil)
				if !errors.Is(err, authn.ErrHMACSecretNotVerified) || got != nil {
					t.Errorf("RequireUV on an unverified assertion: %v", err)
				}
				return nil
			})
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
