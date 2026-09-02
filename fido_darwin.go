// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package fido

import (
	"context"
	"fmt"

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
func Transport() (authn.Transport, error) {
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
	ctx, stop := context.WithCancel(context.Background())
	t := &transport{
		dev:     dev,
		name:    dev.Info().Product,
		reports: make(chan []byte, 32),
		stop:    stop,
	}
	go func() {
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
