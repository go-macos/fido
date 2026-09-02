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
	"time"
)

// ErrNoKey means no FIDO authenticator is attached.
var ErrNoKey = errors.New("fido: no security key is attached")

// readerArmDelay is how long to wait after starting the reader before writing.
// It is a package var so a test does not pay it.
var readerArmDelay = 80 * time.Millisecond

func waitForReader() { time.Sleep(readerArmDelay) }
