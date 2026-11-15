// Copyright (c) the go-macos authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package fido

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestThePINFileIsReadOnlyWhenItIsPrivate(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if pin, err := readPINFile(write("ok", "s3cret pin\r\n", 0o600)); err != nil || pin != "s3cret pin" {
		t.Errorf("a private file: %v (%d chars)", err, len(pin))
	}
	for name, mode := range map[string]os.FileMode{"group": 0o640, "other": 0o604, "world": 0o644} {
		_, err := readPINFile(write(name, "1234", mode))
		if err == nil || !strings.Contains(err.Error(), "0600") {
			t.Errorf("mode %04o was not refused: %v", mode, err)
		}
		if err != nil && strings.Contains(err.Error(), "1234") {
			t.Error("the refusal repeats the PIN")
		}
	}
	if _, err := readPINFile(write("empty", "\n", 0o600)); err == nil {
		t.Error("an empty PIN file was accepted")
	}
	if _, err := readPINFile(filepath.Join(dir, "absent")); err == nil {
		t.Error("a missing file was accepted")
	}
	if _, err := readPINFile(dir); err == nil {
		t.Error("a directory was accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "ok"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPINFile(link); err == nil {
		t.Error("a symlink was followed")
	}
}

func TestThePINFilePathIsTheEnvironmentsPathNotAPIN(t *testing.T) {
	t.Setenv("FIDO_PIN_FILE", "/somewhere/pin")
	if p, err := pinFilePath(); err != nil || p != "/somewhere/pin" {
		t.Errorf("%q, %v", p, err)
	}
	t.Setenv("FIDO_PIN_FILE", "")
	t.Setenv("HOME", "/home/x")
	if p, err := pinFilePath(); err != nil || p != "/home/x/.config/fido-test/pin" {
		t.Errorf("default %q, %v", p, err)
	}
}
