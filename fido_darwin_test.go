// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package fido

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	authn "github.com/go-authn/fido"
	"github.com/go-macos/iokit/hid"
)

// shortWait shortens the run-loop arming delay without removing it.
//
// Removing it entirely made the handshake time out, which is exactly what the
// delay is for: the reader is registered from a goroutine, so with no wait at
// all the first report is written before anything is listening. The fake races
// the same way the hardware does.
func shortWait(t *testing.T) {
	t.Helper()
	old := readerArmDelay
	t.Cleanup(func() { readerArmDelay = old })
	readerArmDelay = 20 * time.Millisecond
}

type fakes struct {
	devices []*hid.Device
	enumErr error
	openErr error
	sendErr error
	sent    [][]byte
	feed    func([]byte)
	reply   func([]byte) [][]byte
}

func install(t *testing.T, f *fakes) {
	t.Helper()
	shortWait(t)
	oe, oo, os_, or := enumerate, openDevice, setReport, readAll
	t.Cleanup(func() { enumerate, openDevice, setReport, readAll = oe, oo, os_, or })

	enumerate = func() ([]*hid.Device, error) { return f.devices, f.enumErr }
	openDevice = func(*hid.Device) error { return f.openErr }
	readAll = func(ctx context.Context, fn func(*hid.Device, []byte), _ *hid.Device) error {
		f.feed = func(b []byte) { fn(nil, b) }
		<-ctx.Done()
		return ctx.Err()
	}
	setReport = func(_ *hid.Device, b []byte) error {
		if f.sendErr != nil {
			return f.sendErr
		}
		f.sent = append(f.sent, append([]byte(nil), b...))
		if f.reply != nil && f.feed != nil {
			for _, r := range f.reply(b) {
				go func(r []byte) { f.feed(r) }(r)
			}
		}
		return nil
	}
}

func TestTransportSaysWhenThereIsNoKey(t *testing.T) {
	install(t, &fakes{})
	if _, err := Transport(); !errors.Is(err, ErrNoKey) {
		t.Errorf("Transport with nothing attached = %v, want ErrNoKey", err)
	}
	if _, err := Open(context.Background()); !errors.Is(err, ErrNoKey) {
		t.Errorf("Open with nothing attached = %v, want ErrNoKey", err)
	}
}

func TestTransportReportsWhatWentWrong(t *testing.T) {
	for _, c := range []struct {
		name string
		f    fakes
		want string
	}{
		{"the enumeration failed", fakes{enumErr: errors.New("boom")}, "look for"},
		{"the key would not open", fakes{devices: []*hid.Device{{}}, openErr: errors.New("busy")}, "cannot open"},
	} {
		t.Run(c.name, func(t *testing.T) {
			install(t, &c.f)
			if _, err := Transport(); err == nil {
				t.Fatal("Transport succeeded")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error says %q, which does not mention %q", err, c.want)
			}
		})
	}
}

// TestTheTransportCarriesAHandshake drives the whole seam: a fake key that
// answers CTAPHID_INIT, through the real portable protocol.
func TestTheTransportCarriesAHandshake(t *testing.T) {
	f := &fakes{devices: []*hid.Device{{}, {}}} // a second device, to be closed
	f.reply = func(sent []byte) [][]byte {
		if (sent[4] &^ 0x80) != authn.CmdInit {
			return nil
		}
		payload := make([]byte, 17)
		copy(payload, sent[7:15]) // echo the nonce
		binary.BigEndian.PutUint32(payload[8:12], 0x0BADF00D)
		payload[12], payload[13], payload[14], payload[15] = 2, 5, 7, 4
		payload[16] = byte(authn.CapWink | authn.CapCBOR)
		p, _ := authn.Split(authn.BroadcastChannel, authn.CmdInit, payload)
		return p
	}
	install(t, f)
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()

	k, err := Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer k.Close()
	if k.Channel() != 0x0BADF00D {
		t.Errorf("channel %#08x", k.Channel())
	}
	if !k.Capabilities().Has(authn.CapCBOR) {
		t.Error("the capabilities did not cross the transport")
	}
	if err := k.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestSendReportsAFailureToWrite(t *testing.T) {
	f := &fakes{devices: []*hid.Device{{}}}
	install(t, f)
	tr, err := Transport()
	if err != nil {
		t.Fatalf("Transport: %v", err)
	}
	defer tr.Close()
	f.sendErr = errors.New("unplugged")
	if err := tr.Send(make([]byte, authn.ReportSize)); err == nil {
		t.Error("Send succeeded on a device that will not take a report")
	}
}

func TestReceiveGivesUpWithItsContext(t *testing.T) {
	install(t, &fakes{devices: []*hid.Device{{}}})
	tr, err := Transport()
	if err != nil {
		t.Fatalf("Transport: %v", err)
	}
	defer tr.Close()
	ctx, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stop()
	if _, err := tr.Receive(ctx); err == nil {
		t.Error("Receive returned a report from a silent device")
	}
	if tr.Name() != "" {
		t.Errorf("Name() = %q for a device with no product string", tr.Name())
	}
	if err := tr.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Errorf("Close twice: %v", err)
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
	if k.Channel() == authn.BroadcastChannel || k.Channel() == 0 {
		t.Errorf("the key handed out channel %#08x, which is not a channel", k.Channel())
	}
	msg := []byte("go-macos/fido round trip")
	echo, err := k.Ping(ctx, msg)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if string(echo) != string(msg) {
		t.Errorf("the key echoed %q, not %q", echo, msg)
	}
}
