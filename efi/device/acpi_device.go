package device

import (
	"bytes"
	"encoding/binary"
	"log"
)

// Subtypes of ACPI Device
// Section 10.3.3 - ACPI Device Path
const (
	_ DevicePathSubType = iota
	ACPIDevice
	ExpandedACPIDevice
)

type ACPIDevicePath struct {
	EFIDevicePath
	HID [4]byte
	UID [4]byte
}

type ExpandedACPIDevicePath struct {
	EFIDevicePath
}

func ParseACPIDevicePath(f *bytes.Reader, efi *EFIDevicePath) EFILoadOptions {
	switch efi.SubType {
	case ACPIDevice:
		a := ACPIDevicePath{EFIDevicePath: *efi}
		if err := binary.Read(f, binary.LittleEndian, &a.HID); err != nil {
			log.Fatal(err)
		}
		if err := binary.Read(f, binary.LittleEndian, &a.UID); err != nil {
			log.Fatal(err)
		}
		return a
	case ExpandedACPIDevice:
		log.Fatalf("Not implemented ACPIDevicePath type: %x\n", efi.SubType)
	default:
		log.Printf("Not implemented ACPIDevicePath type: %x\n", efi.SubType)
	}
	return nil
}
