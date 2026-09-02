// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package fido

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-macos/iokit/hid"
)

// fakeKey drives all five seams so every branch of the transport can be
// exercised on a machine where a real key works -- and, more usefully, on one
// where none is plugged in at all.
type fakeKey struct {
	devices  []*hid.Device
	enumErr  error
	openErr  error
	sendErr  error
	nonceErr error
	// reply, given the packets written so far, returns the reports to deliver.
	reply func(sent [][]byte) [][]byte
	sent  [][]byte
	feed  func([]byte)
}

func install(t *testing.T, f *fakeKey) {
	t.Helper()
	oe, oo, os_, ost, on := enumerate, openDevice, sendReport, stream, newNonce
	t.Cleanup(func() { enumerate, openDevice, sendReport, stream, newNonce = oe, oo, os_, ost, on })

	enumerate = func() ([]*hid.Device, error) { return f.devices, f.enumErr }
	openDevice = func(*hid.Device) error { return f.openErr }
	newNonce = func(b []byte) error {
		if f.nonceErr != nil {
			return f.nonceErr
		}
		for i := range b {
			b[i] = byte(0xA0 + i)
		}
		return nil
	}
	stream = func(ctx context.Context, fn func(*hid.Device, []byte), _ *hid.Device) error {
		f.feed = func(b []byte) { fn(nil, b) }
		<-ctx.Done()
		return ctx.Err()
	}
	sendReport = func(_ *hid.Device, b []byte) error {
		if f.sendErr != nil {
			return f.sendErr
		}
		f.sent = append(f.sent, append([]byte(nil), b...))
		if f.reply != nil && f.feed != nil {
			for _, r := range f.reply(f.sent) {
				go func(r []byte) { f.feed(r) }(r)
			}
		}
		return nil
	}
}

// initReply builds the reply a key gives to CTAPHID_INIT, echoing the nonce
// the fake nonce generator produces.
func initReply(channel uint32, caps byte) []byte {
	payload := make([]byte, 17)
	for i := 0; i < 8; i++ {
		payload[i] = byte(0xA0 + i)
	}
	binary.BigEndian.PutUint32(payload[8:12], channel)
	payload[12], payload[13], payload[14], payload[15] = 2, 5, 7, 4
	payload[16] = caps
	pkts, _ := Split(BroadcastChannel, CmdInit, payload)
	return pkts[0]
}

func oneKey() []*hid.Device { return []*hid.Device{{}} }

func TestOpenSaysWhenThereIsNoKey(t *testing.T) {
	install(t, &fakeKey{})
	if _, err := Open(context.Background()); !errors.Is(err, ErrNoKey) {
		t.Errorf("Open with nothing attached = %v, want ErrNoKey", err)
	}
}

func TestOpenReportsWhatWentWrong(t *testing.T) {
	cases := []struct {
		name string
		f    fakeKey
		want string
	}{
		{"the enumeration failed", fakeKey{enumErr: errors.New("boom")}, "look for"},
		{"the key would not open", fakeKey{devices: oneKey(), openErr: errors.New("busy")}, "cannot open"},
		{"there was no randomness", fakeKey{devices: oneKey(), nonceErr: errors.New("dry")}, "nonce"},
		{"the key would not be written to", fakeKey{devices: oneKey(), sendErr: errors.New("gone")}, "cannot send"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			install(t, &c.f)
			ctx, stop := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer stop()
			_, err := Open(ctx)
			if err == nil {
				t.Fatal("Open succeeded")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q, which does not mention %q", err, c.want)
			}
		})
	}
}

func TestOpenRefusesAnotherProgramsHandshake(t *testing.T) {
	// A reply whose nonce is not ours belongs to somebody else's INIT. Taking
	// it would hand back a channel the key never gave us.
	f := fakeKey{devices: oneKey(), reply: func([][]byte) [][]byte {
		r := initReply(0x11112222, 0x05)
		r[7] ^= 0xFF // corrupt the echoed nonce
		return [][]byte{r}
	}}
	install(t, &f)
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	_, err := Open(ctx)
	if err == nil {
		t.Fatal("Open accepted a reply to another program's INIT")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Errorf("the error says %q, which does not name the nonce", err)
	}
}

func TestOpenRefusesAMalformedReply(t *testing.T) {
	f := fakeKey{devices: oneKey(), reply: func([][]byte) [][]byte {
		pkts, _ := Split(BroadcastChannel, CmdInit, make([]byte, 4)) // far too short
		return [][]byte{pkts[0]}
	}}
	install(t, &f)
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if _, err := Open(ctx); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("Open on a truncated INIT reply = %v", err)
	}
}

// aKeyThatAnswers is the happy path: INIT, then ping echoed, then wink.
func aKeyThatAnswers(channel uint32, caps byte) *fakeKey {
	f := &fakeKey{devices: oneKey()}
	f.reply = func(sent [][]byte) [][]byte {
		last := sent[len(sent)-1]
		cmd := last[4] &^ 0x80
		switch cmd {
		case CmdInit:
			return [][]byte{initReply(channel, caps)}
		case CmdPing:
			n := binary.BigEndian.Uint16(last[5:7])
			pkts, _ := Split(channel, CmdPing, last[7:7+n])
			return pkts
		case CmdWink:
			pkts, _ := Split(channel, CmdWink, nil)
			return pkts
		}
		return nil
	}
	return f
}

func TestAKeyThatAnswers(t *testing.T) {
	f := aKeyThatAnswers(0x33445566, 0x05)
	install(t, f)
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()

	k, err := Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer k.Close()
	if k.Channel() != 0x33445566 {
		t.Errorf("channel %#08x", k.Channel())
	}
	if v := k.Version(); v.CTAPHID != 2 || v.Major != 5 {
		t.Errorf("version %v", v)
	}
	if !k.Capabilities().Has(CapCBOR) {
		t.Error("the capabilities did not survive the handshake")
	}
	if !strings.Contains(k.String(), "5.7.4") {
		t.Errorf("String() = %q", k.String())
	}
	_ = k.Name()

	msg := []byte("multi-factor")
	echo, err := k.Ping(ctx, msg)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !bytes.Equal(echo, msg) {
		t.Errorf("the key echoed %q", echo)
	}
	if err := k.Wink(ctx); err != nil {
		t.Errorf("Wink: %v", err)
	}
	if err := k.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := k.Close(); err != nil {
		t.Errorf("Close twice: %v", err)
	}
}

func TestAKeyThatCannotWinkIsNotAsked(t *testing.T) {
	// Asking anyway would come back as CTAPHID_ERROR, and the caller would
	// have to tell that refusal from a real fault.
	f := aKeyThatAnswers(0x1, byte(CapCBOR|CapNoMsg))
	install(t, f)
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	k, err := Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer k.Close()
	before := len(f.sent)
	if err := k.Wink(ctx); err == nil || !strings.Contains(err.Error(), "cannot wink") {
		t.Errorf("Wink on a key without the capability = %v", err)
	}
	if len(f.sent) != before {
		t.Error("a key that cannot wink was asked to anyway")
	}
}

func TestAKeyThatRefusesIsReportedAsRefusing(t *testing.T) {
	f := aKeyThatAnswers(0x7, 0x05)
	inner := f.reply
	f.reply = func(sent [][]byte) [][]byte {
		if (sent[len(sent)-1][4] &^ 0x80) == CmdPing {
			pkts, _ := Split(0x7, CmdError, []byte{0x06}) // CTAP1_ERR_INVALID_LENGTH
			return pkts
		}
		return inner(sent)
	}
	install(t, f)
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	k, err := Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer k.Close()
	_, err = k.Ping(ctx, []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("a CTAPHID_ERROR reply = %v, want a refusal", err)
	}
	if !strings.Contains(err.Error(), "0x06") {
		t.Errorf("the error says %q, which does not carry the code", err)
	}
}

func TestAKeyThatSaysNothing(t *testing.T) {
	f := aKeyThatAnswers(0x9, 0x05)
	install(t, f)
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	k, err := Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer k.Close()
	f.reply = func([][]byte) [][]byte { return nil } // deaf from here on
	pctx, pstop := context.WithTimeout(ctx, 200*time.Millisecond)
	defer pstop()
	if _, err := k.Ping(pctx, []byte("x")); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("a silent key = %v, want a timeout that names it", err)
	}
}

func TestPingRefusesAMessageTooLong(t *testing.T) {
	f := aKeyThatAnswers(0xb, 0x05)
	install(t, f)
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	k, err := Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer k.Close()
	if _, err := k.Ping(ctx, make([]byte, MaxMessage+1)); !errors.Is(err, ErrTooLong) {
		t.Errorf("Ping of an over-long message = %v, want ErrTooLong", err)
	}
}

// TestARealKeyIfOneIsAttached is the one test that proves the binding rather
// than the logic. It is skipped when no key is plugged in, because a machine
// without one is the ordinary case and a red build would say nothing true.
func TestARealKeyIfOneIsAttached(t *testing.T) {
	devs, err := hid.Devices(hid.Filter{UsagePage: UsagePage, Usage: Usage})
	if err != nil || len(devs) == 0 {
		t.Skip("no security key attached")
	}
	for _, d := range devs {
		d.Close()
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	k, err := Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer k.Close()
	t.Logf("key: %s", k)
	if k.Channel() == BroadcastChannel || k.Channel() == 0 {
		t.Errorf("the key handed out channel %#08x, which is not a channel", k.Channel())
	}
	if k.Version().CTAPHID == 0 {
		t.Error("the key reported CTAPHID version 0")
	}
	msg := []byte("go-macos/fido round trip")
	echo, err := k.Ping(ctx, msg)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !bytes.Equal(echo, msg) {
		t.Errorf("the key echoed %q, not %q", echo, msg)
	}
}

// TestAKeyThatKeepsSayingItIsBusy is the case that breaks everything needing a
// finger. A key waiting to be touched sends CTAPHID_KEEPALIVE about every
// hundred milliseconds for as long as the person takes; a reader that returns
// the first complete message hands back a status byte instead of the answer,
// and does it EARLY, so the failure looks like the key answering nonsense
// rather than like a missing feature.
func TestAKeyThatKeepsSayingItIsBusy(t *testing.T) {
	const ch = 0x5150
	f := aKeyThatAnswers(ch, 0x05)
	inner := f.reply
	f.reply = func(sent [][]byte) [][]byte {
		last := sent[len(sent)-1]
		if (last[4] &^ 0x80) == CmdPing {
			var out [][]byte
			// Three keepalives, status 2 = "waiting for the user", then the
			// real answer.
			for i := 0; i < 3; i++ {
				p, _ := Split(ch, CmdKeepalive, []byte{0x02})
				out = append(out, p[0])
			}
			n := binary.BigEndian.Uint16(last[5:7])
			echo, _ := Split(ch, CmdPing, last[7:7+n])
			return append(out, echo...)
		}
		return inner(sent)
	}
	install(t, f)
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	k, err := Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer k.Close()

	msg := []byte("touch me")
	got, err := k.Ping(ctx, msg)
	if err != nil {
		t.Fatalf("Ping through keepalives: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("got %q, want %q -- a keepalive was returned as the answer", got, msg)
	}
}
