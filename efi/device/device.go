package device

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/foxboron/goefi/efi/attributes"
	"github.com/foxboron/goefi/efi/util"
)

type DevicePathType uint8

const (
	_ DevicePathType = iota
	HardwareDevicePath
	ACPIDevicePath
	MessagingDevicePath
	MediaDevicePath
	BIOSBootSpecificationDevicePath
	EndOfHardwareDevicePath DevicePathType = 127
)

type DevicePathSubType uint8

const (
	NewDevicePath   DevicePathSubType = 1
	NoNewDevicePath DevicePathSubType = 255
)

type EFIDevicePath struct {
	Type    DevicePathType
	SubType DevicePathSubType
	Length  [2]uint8
}

type EFILoadOption struct {
	Attributes         attributes.Attributes
	FilePathListLength uint16
	Description        []byte
	FilePath           []*EFIDevicePath
	Path               []byte
}

type EFILoadOptions interface {
}

func ParseDevicePath(f *bytes.Reader) []*EFILoadOptions {
	var ret []*EFILoadOptions
	for {
		var efidevice EFIDevicePath
		if err := binary.Read(f, binary.LittleEndian, &efidevice); err != nil {
			log.Fatalf("Failed ParseDevicePath binary.Read: %s\n", err)
		}
		switch efidevice.Type {
		case MediaDevicePath:
			d := ParseMediaDevicePath(f, &efidevice)
			ret = append(ret, &d)
		case EndOfHardwareDevicePath:
			log.Printf("Reached end of HardwareDevicePath: %+v\n", efidevice)
			goto end
		default:
			log.Printf("Not implemented EFIDevicePath type: %+v\n", efidevice)
			goto end
		}
	}
end:
	return ret
}

func ParseEFILoadOption(f *bytes.Reader) *EFILoadOption {
	var bootentry EFILoadOption
	if err := binary.Read(f, binary.LittleEndian, &bootentry.Attributes); err != nil {
		fmt.Println(err)
	}
	if err := binary.Read(f, binary.LittleEndian, &bootentry.FilePathListLength); err != nil {
		fmt.Println(err)
	}

	bootentry.Description = util.ReadNullString(f)
	return &bootentry
}
