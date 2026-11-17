// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package fido opens a FIDO security key on macOS and hands it to
// github.com/go-authn/fido as a transport.
//
// The protocol is not here. Framing, the handshake, the commands and every
// command still to come are the same on every operating system and live in
// go-authn/fido; what is macOS about a security key is four calls to IOKit,
// which is what this is.
//
// A FIDO authenticator publishes a HID interface on usage page 0xF1D0 with
// 64-byte reports in both directions. It opens with no entitlement and no user
// consent, so the whole path is reachable in pure Go with CGO_ENABLED=0,
// through go-macos/iokit's own IOKit binding: no framework, no driver, no cgo.
//
//	t, err := fido.Transport()   // or fido.Open(ctx), which also handshakes
//	k, err := authn.Open(ctx, t)
//	defer k.Close()
//	fmt.Println(k)
package fido

import (
	"errors"
	"fmt"
)

// ErrNoKey means no FIDO authenticator is attached.
var ErrNoKey = errors.New("fido: no security key is attached")

// ErrGone means a key that was listed is no longer attached (or no longer has
// the same serial number): it was unplugged, or another one took its place.
var ErrGone = errors.New("fido: that security key is no longer attached")

// Device is one attached security key, as [Devices] lists it. It has the same
// shape as go-gnulinux/fido's Device, so a program can treat both alike.
//
// Opening is by Path, never by position: with two keys attached the order IOKit
// enumerates them in is not promised, so "the first" can be a different key on
// the next call. Path is built from the USB location, which is stable for as
// long as a key stays in the same port.
type Device struct {
	// Path identifies the key, e.g. "iokit:14200000". It is what OpenDevice
	// matches, and what a person can be shown and give back as --device.
	Path string
	// LocationID is the USB location the Path is made from.
	LocationID uint32
	// VendorID and ProductID identify the model.
	VendorID, ProductID uint16
	// Name is the product string, Manufacturer the manufacturer string.
	Name, Manufacturer string
	// Serial is the USB serial number string, empty when the key has none (most
	// do not publish one over HID).
	Serial string
}

// String names the device the way a message a person reads should.
func (d Device) String() string {
	name := d.Name
	if name == "" {
		name = fmt.Sprintf("%04x:%04x", d.VendorID, d.ProductID)
	}
	s := fmt.Sprintf("%s (%04x:%04x) at %s", name, d.VendorID, d.ProductID, d.Path)
	if d.Serial != "" {
		s += ", serial " + d.Serial
	}
	return s
}

// pathOf builds the stable identifier from the USB location.
func pathOf(location uint32) string { return fmt.Sprintf("iokit:%08x", location) }
