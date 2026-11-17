// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"strings"
	"testing"
)

func TestADeviceIsNamedForAPerson(t *testing.T) {
	d := Device{Path: "iokit:14100000", VendorID: 0x1050, ProductID: 0x0407, Name: "YubiKey Bio", Serial: "42"}
	if got := d.String(); got != "YubiKey Bio (1050:0407) at iokit:14100000, serial 42" {
		t.Errorf("%q", got)
	}
	d = Device{Path: "iokit:1", VendorID: 0x1050, ProductID: 0x0407}
	if got := d.String(); !strings.HasPrefix(got, "1050:0407 (1050:0407)") || strings.Contains(got, "serial") {
		t.Errorf("%q", got)
	}
	if pathOf(0x14200000) != "iokit:14200000" {
		t.Error(pathOf(0x14200000))
	}
}
