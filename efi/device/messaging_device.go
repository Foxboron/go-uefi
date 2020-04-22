package device

import (
	"bytes"
	"encoding/binary"
	"log"
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
	USBParentPortNumber [1]byte
	Interface           [1]byte
}

type VendorMessagingDevicePath struct {
	EFIDevicePath
	Guid [16]byte
}

func ParseMessagingDevicePath(f *bytes.Reader, efi *EFIDevicePath) EFILoadOptions {
	switch efi.SubType {
	case MessagingUSB:
		u := USBMessagingDevicePath{EFIDevicePath: *efi}
		if err := binary.Read(f, binary.LittleEndian, &u.USBParentPortNumber); err != nil {
			log.Fatal(err)
		}
		if err := binary.Read(f, binary.LittleEndian, &u.Interface); err != nil {
			log.Fatal(err)
		}
		return u
	case MessagingVendor:
		// Read up rest of the bytes except the end device
		// Not implemented yet
		// m := VendorMessagingDevicePath{EFIDevicePath: *efi}
		b := make([]byte, f.Len()-4)
		if err := binary.Read(f, binary.LittleEndian, b); err != nil {
			log.Fatal(err)
		}
	default:
		log.Printf("Not implemented MessagingDevicePath type: %x\n", efi.SubType)
	}
	return nil
}
