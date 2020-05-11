package efi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/foxboron/goefi/efi/attributes"
	"github.com/foxboron/goefi/efi/device"
	"github.com/foxboron/goefi/efi/signature"
)

func GetBoorOrder() []string {
	ret := []string{}
	s, _ := attributes.ReadEfivars("BootOrder")
	for i := 0; i < len(s.Data); i += 2 {
		val := binary.BigEndian.Uint16([]byte{s.Data[i+1], s.Data[i]})
		ret = append(ret, fmt.Sprintf("Boot%04x\n", val))
	}
	return ret
}

func GetBootEntry(entry string) {
	s, _ := attributes.ReadEfivars(entry)
	f := bytes.NewReader(s.Data)
	_ = device.ParseEFILoadOption(f)
	_ = device.ParseDevicePath(f)
}

func GetSetupMode() []byte {
	attributes.ReadEfivars("SetupMode")
	attributes.ReadEfivars("PK")
	attributes.ReadEfivars("BootOrder")
	return []byte{}
}

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
}

func GetPK() error {
	efivar := "PK"
	s, err := attributes.ReadEfivars(efivar)
	if err != nil {
		log.Fatal(err)
	}
	if (ValidAttributes[efivar] & s.Attributes) != ValidAttributes[efivar] {
		return fmt.Errorf("Invalid bitmask")
	}
	f := bytes.NewReader(s.Data)
	signature.ReadSignatureLists(f)
}

func GetKEK() error {
	efivar := "KEK"
	s, err := attributes.ReadEfivars(efivar)
	if err != nil {
		log.Fatal(err)
	}
	if (ValidAttributes[efivar] & s.Attributes) != ValidAttributes[efivar] {
		return fmt.Errorf("Invalid bitmask")
	}
	f := bytes.NewReader(s.Data)
	signature.ReadSignatureLists(f)
}

func Getdb() error {
	efivar := "db"
	s, err := attributes.ReadEfivars(efivar)
	if err != nil {
		log.Fatal(err)
	}
	if (ValidAttributes[efivar] & s.Attributes) != ValidAttributes[efivar] {
		return fmt.Errorf("Invalid bitmask")
	}
	f := bytes.NewReader(s.Data)
	signature.ReadSignatureLists(f)
}
