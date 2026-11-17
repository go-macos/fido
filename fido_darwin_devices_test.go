// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package fido

import (
	"errors"
	"testing"

	"github.com/go-macos/iokit/hid"
)

// twoKeys installs two attached keys that IOKit lists in the order given, with
// the descriptions given, and records which one was opened.
func twoKeys(t *testing.T, order ...int) (opened *[]*hid.Device, devs []*hid.Device) {
	t.Helper()
	a, b := &hid.Device{}, &hid.Device{}
	infos := map[*hid.Device]hid.Info{
		a: {VendorID: 0x1050, ProductID: 0x0407, Product: "YubiKey OTP+FIDO+CCID", Manufacturer: "Yubico", SerialNumber: "111", LocationID: 0x14200000},
		b: {VendorID: 0x1050, ProductID: 0x0407, Product: "YubiKey Bio", Manufacturer: "Yubico", LocationID: 0x14100000},
	}
	all := []*hid.Device{a, b}
	var listed []*hid.Device
	for _, i := range order {
		listed = append(listed, all[i])
	}
	f := &fakes{devices: listed}
	install(t, f)
	oi, oo := infoOf, openDevice
	t.Cleanup(func() { infoOf, openDevice = oi, oo })
	infoOf = func(d *hid.Device) hid.Info { return infos[d] }
	var got []*hid.Device
	openDevice = func(d *hid.Device) error { got = append(got, d); return nil }
	return &got, []*hid.Device{a, b}
}

func TestDevicesAreListedInAStableOrderWhateverIOKitSays(t *testing.T) {
	for _, order := range [][]int{{0, 1}, {1, 0}} {
		twoKeys(t, order...)
		ds, err := Devices()
		if err != nil || len(ds) != 2 {
			t.Fatalf("%v %v", ds, err)
		}
		if ds[0].Path != "iokit:14100000" || ds[1].Path != "iokit:14200000" {
			t.Errorf("order %v listed %v, %v", order, ds[0].Path, ds[1].Path)
		}
		if ds[0].Name != "YubiKey Bio" || ds[0].Serial != "" || ds[1].Serial != "111" || ds[1].Manufacturer != "Yubico" ||
			ds[1].VendorID != 0x1050 || ds[1].ProductID != 0x0407 || ds[1].LocationID != 0x14200000 {
			t.Errorf("descriptions: %+v %+v", ds[0], ds[1])
		}
	}
}

func TestOpenDeviceOpensTheKeyThatWasChosenNotTheFirst(t *testing.T) {
	for _, order := range [][]int{{0, 1}, {1, 0}} {
		opened, devs := twoKeys(t, order...)
		ds, _ := Devices()
		tr, err := OpenDevice(ds[0]) // the Bio, however the list came
		if err != nil {
			t.Fatal(err)
		}
		tr.Close()
		if len(*opened) != 1 || (*opened)[0] != devs[1] {
			t.Errorf("order %v opened the wrong key", order)
		}
	}
}

func TestAKeyThatWentIsNotReplacedByAnother(t *testing.T) {
	_, _ = twoKeys(t, 0, 1)
	ds, _ := Devices()
	// Same place, another key's serial.
	other := ds[1]
	other.Serial = "999"
	if _, err := OpenDevice(other); !errors.Is(err, ErrGone) {
		t.Errorf("serial mismatch: %v", err)
	}
	// Not attached at all.
	if _, err := OpenDevice(Device{Path: "iokit:00000001"}); !errors.Is(err, ErrGone) {
		t.Errorf("absent: %v", err)
	}
	// A key without a serial matches on Path alone.
	if tr, err := OpenDevice(ds[0]); err != nil {
		t.Errorf("no serial: %v", err)
	} else {
		tr.Close()
	}
}

func TestDeviceListingReportsEnumerationFailure(t *testing.T) {
	boom := errors.New("boom")
	install(t, &fakes{enumErr: boom})
	if _, err := Devices(); !errors.Is(err, boom) {
		t.Errorf("Devices: %v", err)
	}
	if _, err := OpenDevice(Device{}); !errors.Is(err, boom) {
		t.Errorf("OpenDevice: %v", err)
	}
	install(t, &fakes{})
	if ds, err := Devices(); err != nil || len(ds) != 0 {
		t.Errorf("no key: %v %v", ds, err)
	}
}
