package device

import (
	"encoding/binary"
	"io"
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

func (p PCIDevicePath) Format() string {
	return "No format"
}

func ParseHardwareDevicePath(f io.Reader, efi *EFIDevicePath) EFIDevicePaths {
	switch efi.SubType {
	case HardwarePCI:
		p := PCIDevicePath{EFIDevicePath: *efi}
		for _, d := range []interface{}{&p.Function, &p.Device} {
			if err := binary.Read(f, binary.LittleEndian, d); err != nil {
				log.Fatalf("Couldn't Parse PCI Device Path: %s", err)
			}
		}
		return p
	default:
		log.Printf("Not implemented HardwareDevicePath type: %x\n", efi.SubType)
	}
	return nil
}
