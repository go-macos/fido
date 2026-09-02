// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin

package fido

import (
	"context"
	"errors"

	authn "github.com/go-authn/fido"
)

// ErrUnsupported is returned off macOS. The protocol is portable and lives in
// go-authn/fido; only this transport is not.
var ErrUnsupported = errors.New("fido: only macOS is implemented here; see go-authn/fido for the protocol")

// Transport reports [ErrUnsupported].
func Transport() (authn.Transport, error) { return nil, ErrUnsupported }

// Open reports [ErrUnsupported].
func Open(context.Context) (*authn.Key, error) { return nil, ErrUnsupported }
