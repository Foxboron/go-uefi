// +build integrations

package main

import (
	"testing"

	"github.com/foxboron/go-uefi/efi"
)

func TestSecureBootDisabled(t *testing.T) {
	if efi.GetSecureBoot() {
		t.Fatal("in secure boot mode")
	}

	if efi.GetSetupMode() {
		t.Fatal("in setup mode")
	}
}
