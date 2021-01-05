package main

import (
	"testing"

	"github.com/foxboron/go-uefi/efi/attributes"
)

func TestReadSetupMode(t *testing.T) {
	if sm, err := attributes.ReadEfivars("SetupMode"); err == nil {
		if sm.Data[0] == 0 {
			t.Errorf("Not in Setup Mode: %+v", sm.Data)
		}
	}
	if sb, err := attributes.ReadEfivars("SecureBoot"); err == nil {
		if sb.Data[0] == 1 {
			t.Errorf("Secure Boot enabled: %+v", sb.Data)
		}
	}

}
