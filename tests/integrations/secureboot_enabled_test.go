// +build integrations

package main

import (
	"testing"

	"github.com/foxboron/go-uefi/efi"
)

func TestSecureBootEnabled(t *testing.T) {
	if !efi.GetSecureBoot() {
		t.Fatal("not in secure boot mode")
	}

	if !efi.GetSetupMode() {
		t.Fatal("not in setup mode")
	}
}
