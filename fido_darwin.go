// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package fido

import (
	"context"
	"fmt"
	"sort"
	"time"

	authn "github.com/go-authn/fido"
	"github.com/go-macos/iokit/hid"
)

// UsagePage is the HID usage page every FIDO authenticator publishes, and
// Usage the usage within it. Matching on these rather than on a vendor id is
// what makes this work with any key rather than one make.
const (
	UsagePage uint16 = 0xF1D0
	Usage     uint16 = 0x01
)

// The seams, so a test can drive a device that refuses to open and one that
// cannot be written to, on a machine where a real key works.
var (
	enumerate = func() ([]*hid.Device, error) {
		return hid.Devices(hid.Filter{UsagePage: UsagePage, Usage: Usage})
	}
	openDevice = func(d *hid.Device) error { return d.Open() }
	setReport  = func(d *hid.Device, b []byte) error { return d.SetReport(hid.Output, 0, b) }
	readAll    = func(ctx context.Context, fn func(*hid.Device, []byte), d *hid.Device) error {
		return hid.Stream(ctx, fn, d)
	}
)

// readerArmDelay is how long to wait after starting the reader before writing
// to the device. It is a package var so a test does not pay the whole of it.
var readerArmDelay = 80 * time.Millisecond

func waitForReader() { time.Sleep(readerArmDelay) }

// transport carries CTAPHID reports over IOKit.
type transport struct {
	dev  *hid.Device
	name string
	// reports carries every input report for the life of the device. ONE
	// reader is started, in Open, and never restarted: a second hid.Stream
	// opened on a device whose first was cancelled delivers nothing, silently,
	// and the symptom is a key that answers the handshake and then never
	// again.
	reports chan []byte
	stop    context.CancelFunc
	// done is closed when the reader has RETURNED, which is not the same as
	// having been cancelled. Closing the device while the reader is still
	// inside IOKit, holding the reference, is a use-after-free: it jumps into
	// freed memory and the crash names a code address rather than anything
	// recognisable. Found by -race with a key attached.
	done chan struct{}
}

// Name is what the key calls itself.
func (t *transport) Name() string { return t.name }

// Send writes one report.
func (t *transport) Send(report []byte) error { return setReport(t.dev, report) }

// Receive returns the next report, or what went wrong waiting for it.
func (t *transport) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-t.reports:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close stops the reader and releases the device.
func (t *transport) Close() error {
	if t.stop != nil {
		t.stop()
		t.stop = nil
		// Wait for the reader to be OUT of IOKit before the device goes.
		<-t.done
	}
	if t.dev == nil {
		return nil
	}
	d := t.dev
	t.dev = nil
	return d.Close()
}

// Transport opens the first attached security key and returns it as a
// transport for github.com/go-authn/fido.
//
// It is deliberately the only thing this package exports. Everything a caller
// then does -- the handshake, the commands, the framing -- is the same on every
// operating system and lives there; what is macOS about a security key is
// four calls to IOKit.
//
// [ErrNoKey] means none is attached, which is an ordinary state and not a
// fault: a person can be asked to plug one in.
//
// ⛔ With more than one key attached this takes whichever IOKit lists first,
// and that order is not promised. A program that changes anything on the key
// (a PIN, a fingerprint, a credential) must use [Devices] and [OpenDevice], so
// that the key acted on is one a person chose and was shown.
func Transport() (authn.Transport, error) {
	devs, err := enumerate()
	if err != nil {
		return nil, fmt.Errorf("fido: cannot look for a security key: %w", err)
	}
	if len(devs) == 0 {
		return nil, ErrNoKey
	}
	for _, extra := range devs[1:] {
		extra.Close()
	}
	return start(devs[0])
}

// infoOf reads a device's description; a seam, because a test cannot build a
// hid.Device with a description.
var infoOf = func(d *hid.Device) hid.Info { return d.Info() }

func describe(h *hid.Device) Device {
	i := infoOf(h)
	return Device{
		Path: pathOf(i.LocationID), LocationID: i.LocationID,
		VendorID: i.VendorID, ProductID: i.ProductID,
		Name: i.Product, Manufacturer: i.Manufacturer, Serial: i.SerialNumber,
	}
}

// Devices lists the attached security keys without opening any of them, in a
// stable order (by Path). It asks nothing of the keys, so it needs no touch.
// An empty list is not an error.
func Devices() ([]Device, error) {
	hs, err := enumerate()
	if err != nil {
		return nil, fmt.Errorf("fido: cannot look for a security key: %w", err)
	}
	out := make([]Device, 0, len(hs))
	for _, h := range hs {
		out = append(out, describe(h))
		h.Close()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// OpenDevice opens the key d describes, matched by Path (and by Serial when d
// has one), and returns it as a transport. A key that has gone, or whose place
// another took, is [ErrGone]: never a different key opened in its stead.
func OpenDevice(d Device) (authn.Transport, error) {
	hs, err := enumerate()
	if err != nil {
		return nil, fmt.Errorf("fido: cannot look for a security key: %w", err)
	}
	var found *hid.Device
	for _, h := range hs {
		c := describe(h)
		if found == nil && c.Path == d.Path && (d.Serial == "" || c.Serial == d.Serial) {
			found = h
			continue
		}
		h.Close()
	}
	if found == nil {
		return nil, fmt.Errorf("%w: %s", ErrGone, d.Path)
	}
	return start(found)
}

// start opens dev and begins reading it.
func start(dev *hid.Device) (authn.Transport, error) {
	if err := openDevice(dev); err != nil {
		dev.Close()
		return nil, fmt.Errorf("fido: cannot open %s: %w", infoOf(dev).Product, err)
	}
	ctx, stop := context.WithCancel(context.Background())
	t := &transport{
		dev:     dev,
		name:    infoOf(dev).Product,
		reports: make(chan []byte, 32),
		stop:    stop,
		done:    make(chan struct{}),
	}
	go func() {
		defer close(t.done)
		_ = readAll(ctx, func(_ *hid.Device, b []byte) {
			c := make([]byte, len(b))
			copy(c, b)
			select {
			case t.reports <- c:
			case <-ctx.Done():
			}
		}, dev)
	}()
	// The callback is registered on a run loop, so there is a moment between
	// starting the reader and it being armed. Measured: without this wait, one
	// exchange in three was lost -- and lost in the way that looks like a key
	// that does not answer.
	waitForReader()
	return t, nil
}

// Open finds a key, opens it and does the CTAPHID handshake, which is what
// almost every caller wants.
func Open(ctx context.Context) (*authn.Key, error) {
	t, err := Transport()
	if err != nil {
		return nil, err
	}
	return authn.Open(ctx, t)
}
