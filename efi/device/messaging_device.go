package device

import (
	"bytes"
	"encoding/binary"
	"log"

	"github.com/foxboron/goefi/efi/util"
)

// Subtypes of Messaging Device Path
// Section 10.3.4
const (
	_ DevicePathSubType = iota
	_
	_
	_
	_
	MessagingUSB
	_
	_
	_
	_
	MessagingVendor
)

type USBMessagingDevicePath struct {
	EFIDevicePath
	USBParentPortNumber uint8
	Interface           uint8
}

type VendorMessagingDevicePath struct {
	EFIDevicePath
	Guid util.EFIGUID
}

func ParseMessagingDevicePath(f *bytes.Reader, efi *EFIDevicePath) EFIDevicePaths {
	switch efi.SubType {
	case MessagingUSB:
		u := USBMessagingDevicePath{EFIDevicePath: *efi}
		for _, d := range []interface{}{&u.USBParentPortNumber, &u.Interface} {
			if err := binary.Read(f, binary.LittleEndian, d); err != nil {
				log.Fatalf("Couldn't parse USB Messaging Device Path: %s", err)
			}
		}
		return u
	case MessagingVendor:
		m := VendorMessagingDevicePath{EFIDevicePath: *efi}
		if err := binary.Read(f, binary.LittleEndian, &m.Guid); err != nil {
			log.Fatalf("Could not parse Vendor Messaging Device Path: %s", err)
		}
	default:
		log.Printf("Not implemented MessagingDevicePath type: %x\n", efi.SubType)
	}
	return nil
}
