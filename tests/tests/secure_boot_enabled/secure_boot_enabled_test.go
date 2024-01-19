package main

import (
	"testing"

	"github.com/foxboron/go-uefi/efi"
	"github.com/hugelgupf/vmtest/guest"
)

func TestSecureBootEnabled(t *testing.T) {
	guest.SkipIfNotInVM(t)

	if !efi.GetSecureBoot() {
		t.Fatal("not in secure boot mode")
	}

	if efi.GetSetupMode() {
		t.Fatal("in setup mode")
	}
}
