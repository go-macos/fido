// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin

package fido

import "context"

// Key is not implemented off macOS. The framing above is portable and tested
// everywhere; only the transport is not.
type Key struct{}

// Name reports nothing.
func (k *Key) Name() string { return "" }

// Version reports nothing.
func (k *Key) Version() Version { return Version{} }

// Capabilities reports nothing.
func (k *Key) Capabilities() Capabilities { return 0 }

// Channel reports nothing.
func (k *Key) Channel() uint32 { return 0 }

// Close does nothing.
func (k *Key) Close() error { return nil }

// Open reports [ErrUnsupported].
func Open(context.Context) (*Key, error) { return nil, ErrUnsupported }

// Ping reports [ErrUnsupported].
func (k *Key) Ping(context.Context, []byte) ([]byte, error) { return nil, ErrUnsupported }

// Wink reports [ErrUnsupported].
func (k *Key) Wink(context.Context) error { return ErrUnsupported }
