// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin

package fido

import (
	"context"
	"errors"
	"testing"
)

// TestEveryCallRefusesOffMacOS, and names where the portable half lives rather
// than leaving a caller to wonder whether the protocol works at all.
func TestEveryCallRefusesOffMacOS(t *testing.T) {
	if _, err := Transport(); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Transport = %v, want ErrUnsupported", err)
	}
	if _, err := Open(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Open = %v, want ErrUnsupported", err)
	}
	if !errors.Is(ErrUnsupported, ErrUnsupported) || len(ErrUnsupported.Error()) == 0 {
		t.Error("the error says nothing")
	}
}
