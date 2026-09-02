// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package fido

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/go-macos/iokit/hid"
)

// UsagePage is the HID usage page every FIDO authenticator publishes, and
// usage 1 within it. Matching on this rather than on a vendor id is what makes
// the package work with any key rather than one make.
const (
	UsagePage uint16 = 0xF1D0
	Usage     uint16 = 0x01
)

// The seams, so a test can drive a key that answers, a key that refuses to
// open, and a key that says nothing, on a machine where a real one works.
var (
	enumerate = func() ([]*hid.Device, error) {
		return hid.Devices(hid.Filter{UsagePage: UsagePage, Usage: Usage})
	}
	openDevice = func(d *hid.Device) error { return d.Open() }
	sendReport = func(d *hid.Device, b []byte) error { return d.SetReport(hid.Output, 0, b) }
	stream     = func(ctx context.Context, fn func(*hid.Device, []byte), d *hid.Device) error {
		return hid.Stream(ctx, fn, d)
	}
	newNonce = func(b []byte) error { _, err := rand.Read(b); return err }
)

// Key is an open authenticator with a negotiated channel.
type Key struct {
	dev     *hid.Device
	info    hid.Info
	channel uint32
	version Version
	caps    Capabilities

	// reports carries every input report for the life of the key. ONE reader
	// is started, in Open, and never restarted: a second hid.Stream opened on
	// a device whose first was cancelled delivers nothing, silently, and the
	// symptom is a key that answers the handshake and then never again.
	reports  chan []byte
	stopRead context.CancelFunc
}

// Name is what the key calls itself.
func (k *Key) Name() string { return k.info.Product }

// Version is the key's firmware and transport version.
func (k *Key) Version() Version { return k.version }

// Capabilities is what the key said it can do.
func (k *Key) Capabilities() Capabilities { return k.caps }

// Channel is the negotiated channel id.
func (k *Key) Channel() uint32 { return k.channel }

// String renders the key the way a log reads.
func (k *Key) String() string {
	return fmt.Sprintf("%s (%s, %s) on channel %#08x", k.info.Product, k.version, k.caps, k.channel)
}

// Close releases the key.
func (k *Key) Close() error {
	if k.stopRead != nil {
		k.stopRead()
		k.stopRead = nil
	}
	if k.dev == nil {
		return nil
	}
	err := k.dev.Close()
	k.dev = nil
	return err
}

// Open finds the first attached authenticator, opens it and negotiates a
// channel.
//
// The handshake is not optional and is done here rather than left to the
// caller: every later message carries the channel id, so a Key without one
// could not be used for anything, and returning one would be handing back a
// half-built object to be misused.
//
// [ErrNoKey] means none is attached, which is an ordinary state and not a
// fault: a person can be asked to plug one in.
func Open(ctx context.Context) (*Key, error) {
	devs, err := enumerate()
	if err != nil {
		return nil, fmt.Errorf("fido: cannot look for a security key: %w", err)
	}
	if len(devs) == 0 {
		return nil, ErrNoKey
	}
	dev := devs[0]
	for _, extra := range devs[1:] {
		extra.Close()
	}
	if err := openDevice(dev); err != nil {
		dev.Close()
		return nil, fmt.Errorf("fido: cannot open %s: %w", dev.Info().Product, err)
	}
	k := &Key{dev: dev, info: dev.Info(), channel: BroadcastChannel, reports: make(chan []byte, 32)}
	rctx, stopRead := context.WithCancel(context.Background())
	k.stopRead = stopRead
	go func() {
		_ = stream(rctx, func(_ *hid.Device, b []byte) {
			c := make([]byte, len(b))
			copy(c, b)
			select {
			case k.reports <- c:
			case <-rctx.Done():
			}
		}, dev)
	}()
	// The callback is registered on a run loop, so there is a moment between
	// starting the reader and it being armed. Measured: without this wait, one
	// exchange in three was lost.
	time.Sleep(80 * time.Millisecond)

	var nonce [8]byte
	if err := newNonce(nonce[:]); err != nil {
		k.Close()
		return nil, fmt.Errorf("fido: cannot make a nonce: %w", err)
	}
	reply, err := k.roundTrip(ctx, CmdInit, nonce[:])
	if err != nil {
		k.Close()
		return nil, err
	}
	init, err := ParseInit(reply)
	if err != nil {
		k.Close()
		return nil, fmt.Errorf("fido: the key's INIT reply was malformed: %w", err)
	}
	if init.Nonce != nonce {
		k.Close()
		return nil, fmt.Errorf("fido: the key answered another program's INIT (nonce %x, wanted %x)", init.Nonce, nonce)
	}
	k.channel, k.version, k.caps = init.Channel, init.Version, init.Caps
	return k, nil
}

// Ping sends data and returns what came back, which a working channel returns
// unchanged. It is how to check a key is still there without asking it to do
// anything.
func (k *Key) Ping(ctx context.Context, data []byte) ([]byte, error) {
	return k.roundTrip(ctx, CmdPing, data)
}

// Wink makes the key blink, when it said it can.
//
// It is the one thing here a PERSON can see, which is what makes it useful for
// more than diagnostics: asked to prove which key is which, or that the key is
// the one on the desk rather than one left in a hub, a blink answers.
//
// A key without [CapWink] is not asked, because a key that does not wink
// answers CTAPHID_ERROR and the caller would have to tell that refusal from a
// real fault.
func (k *Key) Wink(ctx context.Context) error {
	if !k.caps.Has(CapWink) {
		return fmt.Errorf("fido: %s cannot wink", k.info.Product)
	}
	_, err := k.roundTrip(ctx, CmdWink, nil)
	return err
}

// roundTrip sends one message and waits for its reply.
//
// The reader is started BEFORE the write. Started after, it races the key: a
// key answers a ping in under a millisecond, and the reply is gone before
// anything is listening -- which reads as a key that never answered.
func (k *Key) roundTrip(ctx context.Context, cmd byte, data []byte) ([]byte, error) {
	packets, err := Split(k.channel, cmd, data)
	if err != nil {
		return nil, err
	}
	// Anything left from an earlier exchange is not an answer to this one. A
	// key that was slow, or a wink whose reply arrived after a timeout, would
	// otherwise be returned as the reply to the NEXT question.
	for {
		select {
		case <-k.reports:
			continue
		default:
		}
		break
	}
	for _, p := range packets {
		if err := sendReport(k.dev, p); err != nil {
			return nil, fmt.Errorf("fido: cannot send to %s: %w", k.info.Product, err)
		}
	}
	rc := NewReassembler(k.channel)
	for {
		select {
		case b := <-k.reports:
			msg, done, err := rc.Feed(b)
			if err != nil {
				// A report for another channel is another program talking to
				// the same key. Waiting is right: ours is still coming.
				if err == ErrWrongChannel {
					continue
				}
				return nil, err
			}
			if !done {
				continue
			}
			if msg.Cmd == CmdKeepalive {
				// The key is still working -- almost always waiting for a
				// finger. It sends one of these about every hundred
				// milliseconds for as long as the person takes. Returning it
				// would hand the caller a status byte where the answer goes.
				continue
			}
			if msg.IsError() {
				code := byte(0)
				if len(msg.Data) > 0 {
					code = msg.Data[0]
				}
				return nil, fmt.Errorf("fido: %s refused the request (CTAPHID error %#02x)", k.info.Product, code)
			}
			return msg.Data, nil
		case <-ctx.Done():
			return nil, fmt.Errorf("fido: %s did not answer: %w", k.info.Product, ctx.Err())
		}
	}
}
