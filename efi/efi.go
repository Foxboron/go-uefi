package efi

// Top level API for goefi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/foxboron/goefi/efi/attributes"
	"github.com/foxboron/goefi/efi/device"
	"github.com/foxboron/goefi/efi/signature"
)

// Keeps track of expected attributes for each variable
var ValidAttributes = map[string]attributes.Attributes{
	"SetupMode": attributes.EFI_VARIABLE_NON_VOLATILE |
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS,
	"PK": attributes.EFI_VARIABLE_NON_VOLATILE |
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
		attributes.EFI_VARIABLE_RUNTIME_ACCESS |
		attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
	"KEK": attributes.EFI_VARIABLE_NON_VOLATILE |
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
		attributes.EFI_VARIABLE_RUNTIME_ACCESS |
		attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
	"db": attributes.EFI_VARIABLE_NON_VOLATILE |
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
		attributes.EFI_VARIABLE_RUNTIME_ACCESS |
		attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
}

func GetBoorOrder() []string {
	ret := []string{}
	s, _ := attributes.ReadEfivars("BootOrder")
	for i := 0; i < len(s.Data); i += 2 {
		val := binary.BigEndian.Uint16([]byte{s.Data[i+1], s.Data[i]})
		ret = append(ret, fmt.Sprintf("Boot%04x\n", val))
	}
	return ret
}

func GetBootEntry(entry string) *device.EFILoadOption {
	s, _ := attributes.ReadEfivars(entry)
	f := bytes.NewReader(s.Data)
	loadOption := device.ParseEFILoadOption(f)
	loadOption.FilePath = device.ParseDevicePath(f)
	return loadOption
}

// GetSetupMode returns if setup mode has been enabled on the machine.
func GetSetupMode() bool {
	if sm, err := attributes.ReadEfivars("SetupMode"); err == nil {
		if sm.Data[0] == 1 {
			return true
		}
	}
	return false
}

// GetSecureBoot returns if secure boot has been enabled on the machine.
func GetSecureBoot() bool {
	if sm, err := attributes.ReadEfivars("SecureBoot"); err == nil {
		if sm.Data[0] == 1 {
			return true
		}
	}
	return false
}

func GetPK() error {
	efivar := "PK"
	s, err := attributes.ReadEfivars(efivar)
	if err != nil {
		log.Fatal(err)
	}
	if (ValidAttributes[efivar] & s.Attributes) != ValidAttributes[efivar] {
		return fmt.Errorf("invalid bitmask")
	}
	f := bytes.NewReader(s.Data)
	signature.ReadSignatureLists(f)
	return nil
}

func GetKEK() error {
	efivar := "KEK"
	s, err := attributes.ReadEfivars(efivar)
	if err != nil {
		log.Fatal(err)
	}
	if (ValidAttributes[efivar] & s.Attributes) != ValidAttributes[efivar] {
		return fmt.Errorf("invalid bitmask")
	}
	f := bytes.NewReader(s.Data)
	signature.ReadSignatureLists(f)
	return nil
}

func Getdb() error {
	efivar := "db"
	s, err := attributes.ReadEfivars(efivar)
	if err != nil {
		log.Fatal(err)
	}
	if (ValidAttributes[efivar] & s.Attributes) != ValidAttributes[efivar] {
		return fmt.Errorf("invalid bitmask")
	}
	f := bytes.NewReader(s.Data)
	signature.ReadSignatureLists(f)
	return nil
}
