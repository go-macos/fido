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

// TestEveryCallRefusesOffMacOS. The framing above is portable and is tested
// everywhere; the transport is not, and says so rather than returning a Key
// that would answer every question with a zero.
func TestEveryCallRefusesOffMacOS(t *testing.T) {
	if _, err := Open(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Open = %v, want ErrUnsupported", err)
	}
	var k Key
	if _, err := k.Ping(context.Background(), nil); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Ping = %v, want ErrUnsupported", err)
	}
	if err := k.Wink(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Wink = %v, want ErrUnsupported", err)
	}
	if err := k.Close(); err != nil {
		t.Errorf("Close = %v, want nil", err)
	}
	if k.Name() != "" || k.Channel() != 0 || k.Capabilities() != 0 || k.Version() != (Version{}) {
		t.Error("the stub key claims to know something about a key")
	}
}
