package device

import (
	"encoding/binary"
	"io"
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

func (a ACPIDevicePath) Format() string {
	return "No format"
}

func ParseACPIDevicePath(f io.Reader, efi *EFIDevicePath) EFIDevicePaths {
	switch efi.SubType {
	case ACPIDevice:
		a := ACPIDevicePath{EFIDevicePath: *efi}
		for _, i := range []interface{}{&a.HID, &a.UID} {
			if err := binary.Read(f, binary.LittleEndian, i); err != nil {
				log.Fatalf("Can't prase ACPI Device Path: %s", err)
			}
		}
		return a
	case ExpandedACPIDevice:
		log.Fatalf("Not implemented ACPIDevicePath type: %x\n", efi.SubType)
	default:
		log.Printf("Not implemented ACPIDevicePath type: %x\n", efi.SubType)
	}
	return nil
}
