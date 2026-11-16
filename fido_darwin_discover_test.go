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

// TestRealKeyDiscoverableNextAssertion MEASURES what CTAP 2.1 §6.3 leaves
// open: whether authenticatorGetNextAssertion carries the hmac-secret output
// of each further discoverable credential, and whether the whole walk costs
// one gesture. go-theca/theca's FIDO2 design depends on the answer
// (go-theca/theca#15). It runs only with
//
//	FIDO_REAL=1 go test -run TestRealKeyDiscoverableNextAssertion -v
//
// and uses the same PIN file and modes as TestRealKeyHMACSecretAndUV.
//
// ⚠ It leaves TWO discoverable credentials on the key, under the relying
// party "go-macos-fido-discover.invalid" (a YubiKey 5.7 holds 100). Remove
// them with the key's credential management tool if the slots matter.
//
// Gestures: 2 registrations, 1 walk, 1 targeted check = 4 touches.
// It logs counts, presence and equalities, never a secret.
//
// Measured 2026-11-16 on a YubiKey 5 (firmware 5.7.4, PIN mode): two
// credentials announced, both assertions of ONE walk (one touch) carry the
// hmac-secret output, and the next assertion's output equals a direct
// assertion of that credential. An authenticator with a display may behave
// otherwise (§6.2.2 step 12: the person picks one).
func TestRealKeyDiscoverableNextAssertion(t *testing.T) {
	if os.Getenv("FIDO_REAL") != "1" {
		t.Skip("NOT RUN: set FIDO_REAL=1 with a key attached")
	}
	const rp = "go-macos-fido-discover.invalid"
	cdh := sha256.Sum256([]byte("go-macos/fido discoverable walk test"))
	salt1 := sha256.Sum256([]byte("discover salt one"))
	salt2 := sha256.Sum256([]byte("discover salt two"))

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
	t.Logf("authenticator: %s", info)
	if !contains(info.Extensions, "hmac-secret") || !info.Has("rk") || !info.Has("pinUvAuthToken") {
		t.Skip("NOT RUN: the key lacks hmac-secret, rk or pinUvAuthToken")
	}
	proto := authn.PINProtocolOne
	for _, p := range info.PINProtocols {
		if p == uint(authn.PINProtocolTwo) {
			proto = authn.PINProtocolTwo
		}
	}
	bio := info.Has("uv")
	touch := "Touch the YubiKey now (30 s)"
	var pin string
	if bio {
		touch = "Touch the YubiKey fingerprint sensor now (30 s)"
	} else {
		path, err := pinFilePath()
		if err != nil {
			t.Fatalf("where the PIN file is: %v", err)
		}
		if pin, err = readPINFile(path); err != nil {
			t.Skipf("NOT RUN: the PIN file: %v", err)
		}
	}

	step := 0
	finger := func(what string, f func(ctx context.Context) error) error {
		step++
		fmt.Fprintf(os.Stderr, "\n[step %d] %s\n%s\n", step, what, touch)
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return f(c)
	}
	notRun := func(err error) {
		// A YubiKey answers CTAP2_ERR_OPERATION_DENIED (0x27) when nobody
		// touches it in time, before our own 30 s context runs out (measured
		// 2026-11-16: 29.03 s). Nobody being there says nothing about the code.
		if errors.Is(err, context.DeadlineExceeded) || (err != nil && strings.Contains(err.Error(), "(0x27)")) {
			t.Skipf("NOT RUN: nobody touched the key in time at step %d (%v)", step, err)
		}
	}
	token := func(what string, perms authn.Permissions) authn.Token {
		t.Helper()
		if !bio {
			c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			r, err := k.PINRetries(c)
			if err != nil {
				t.Fatalf("PIN retries: %v", err)
			}
			if r.PIN < minRetries || r.PowerCycle {
				t.Fatalf("STOPPED: %d PIN retries left; refusing to go below %d", r.PIN, minRetries)
			}
			tok, err := k.PINToken(c, pin, proto, perms, rp)
			if err != nil {
				t.Fatalf("PIN token for %s: %v", what, err)
			}
			return tok
		}
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

	// Two discoverable credentials, credProtect 3, as theca would make them.
	var ids [][]byte
	for i := range 2 {
		tok := token("register", authn.PermMakeCredential)
		var att *authn.Attestation
		err := finger(fmt.Sprintf("confirm registration %d of 2", i+1), func(c context.Context) (err error) {
			att, err = k.MakeCredential(c, authn.MakeCredentialRequest{
				ClientDataHash: cdh[:],
				RP:             authn.RelyingParty{ID: rp, Name: "go-macos/fido discoverable test"},
				User:           authn.User{ID: []byte(fmt.Sprintf("discover-%d-%d", i, time.Now().UnixNano()))},
				Options:        map[string]bool{"rk": true},
				Token:          tok,
				Extensions:     authn.Extensions{HMACSecret: true, CredProtect: authn.CredProtectRequired},
			})
			return err
		})
		notRun(err)
		if err != nil {
			t.Fatalf("MakeCredential %d: %v", i+1, err)
		}
		ids = append(ids, att.Parsed.CredentialID)
	}

	// THE MEASUREMENT: one verified request, empty allowList, two salts.
	tok := token("verify for the walk", authn.PermGetAssertion)
	var all []*authn.Assertion
	err = finger("confirm ONE assertion: the key should answer for every credential", func(c context.Context) (err error) {
		all, err = k.GetAssertions(c, authn.GetAssertionRequest{
			RPID: rp, ClientDataHash: cdh[:], Token: tok,
			HMACSecret: &authn.HMACSecret{Protocol: proto, Salt1: salt1[:], Salt2: salt2[:], RequireUV: true},
		}, 128)
		return err
	})
	notRun(err)
	if err != nil {
		t.Fatalf("GetAssertions: %v", err)
	}
	t.Logf("numberOfCredentials announced: %d; assertions received: %d (gestures for the walk: 1 prompt)", all[0].Available, len(all))
	withOutput := 0
	for i, a := range all {
		has := a.HMACSecret != nil
		if has {
			withOutput++
		}
		t.Logf("assertion %d: credential %d bytes, UV=%v, hmac-secret output: %v", i+1, len(a.Credential.ID), a.Parsed.Flags.Has(authn.FlagUV), has)
	}
	t.Logf("RESULT: %d of %d assertions carry the hmac-secret output", withOutput, len(all))
	if len(all) < 2 {
		t.Fatalf("expected at least the 2 credentials just made, got %d", len(all))
	}

	// The older credential (registered first) comes second (newest first).
	// Ask it directly and compare, so an output found on a next assertion is
	// known to be THAT credential's, not a copy of the first.
	var older *authn.Assertion
	for _, a := range all {
		if bytes.Equal(a.Credential.ID, ids[0]) {
			older = a
		}
	}
	if older == nil {
		t.Fatal("the first credential registered is not among the answers")
	}
	tok = token("verify for the direct check", authn.PermGetAssertion)
	var direct *authn.Assertion
	err = finger("confirm the direct assertion of the older credential", func(c context.Context) (err error) {
		direct, err = k.GetAssertion(c, authn.GetAssertionRequest{
			RPID: rp, ClientDataHash: cdh[:], Token: tok, Allow: []authn.Credential{{ID: ids[0]}},
			HMACSecret: &authn.HMACSecret{Protocol: proto, Salt1: salt1[:], Salt2: salt2[:], RequireUV: true},
		})
		return err
	})
	notRun(err)
	if err != nil {
		t.Fatalf("direct assertion: %v", err)
	}
	if older.HMACSecret == nil {
		t.Logf("RESULT: the older credential's next assertion has NO hmac-secret output; direct output %d+%d bytes",
			len(direct.HMACSecret.First), len(direct.HMACSecret.Second))
		return
	}
	same := bytes.Equal(older.HMACSecret.First, direct.HMACSecret.First) && bytes.Equal(older.HMACSecret.Second, direct.HMACSecret.Second)
	t.Logf("RESULT: the next assertion's output equals the direct one: %v", same)
	if !same {
		t.Error("a next assertion carried an hmac-secret output that is not its credential's")
	}
}
