package device

import (
	"bytes"
	"encoding/binary"
	"log"
)

// Subtypes of ACPI Device
// Section 10.3.1 - Hardware Device Path
const (
	_ DevicePathSubType = iota
	HardwarePCI
	HardwarePCCARD
	HardwareMemoryMapped
	HardwareVendor
	HardwareController
	HardwareBMC
)

type PCIDevicePath struct {
	EFIDevicePath
	Function [1]byte
	Device   [1]byte
}

func ParseHardwareDevicePath(f *bytes.Reader, efi *EFIDevicePath) EFIDevicePaths {
	switch efi.SubType {
	case HardwarePCI:
		p := PCIDevicePath{EFIDevicePath: *efi}
		if err := binary.Read(f, binary.LittleEndian, &p.Function); err != nil {
			log.Fatal(err)
		}
		if err := binary.Read(f, binary.LittleEndian, &p.Device); err != nil {
			log.Fatal(err)
		}
		return p
	default:
		log.Printf("Not implemented HardwareDevicePath type: %x\n", efi.SubType)
	}
	return nil
}
