package device

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"github.com/foxboron/go-uefi/efi/attributes"
	"github.com/foxboron/go-uefi/efi/util"
)

//	Section 3.1.3 Load Options
//
// Page 71
type EFILoadOption struct {
	Attributes         attributes.Attributes
	FilePathListLength uint16
	Description        string
	FilePath           []EFIDevicePaths
	OptionalData       []byte // TODO: Implement
}

func (e *EFILoadOption) Unmarshal(b *bytes.Buffer) error {
	elo, err := ParseEFILoadOption(b)
	if err != nil {
		return err
	}
	elo.FilePath, err = ParseDevicePath(b)
	if err != nil {
		return fmt.Errorf("could parse device path: %w", err)
	}
	*e = *elo
	return nil
}

// Section 10.3 Device Path Nodes
// Page 286
type DevicePathType uint8

const (
	_ DevicePathType = iota
	Hardware
	ACPI
	MessagingDevicePath
	MediaDevicePath
	BIOSBootSpecificationDevicePath
	EndOfHardwareDevicePath DevicePathType = 127
)

// Section 10.3.1 Generic Device Path Structures
// Page 287
type DevicePathSubType uint8

// Table 45. Device Path End Structure
// Subtypes of EndofHardwareDevicePath
const (
	NewDevicePath   DevicePathSubType = 1
	NoNewDevicePath DevicePathSubType = 255
)

// Section 10.2 EFI Device Path Protocol
// Page 285
type EFIDevicePath struct {
	Type    DevicePathType
	SubType DevicePathSubType
	Length  [2]uint8
}

type EFIDevicePaths interface {
	Format() string
}

func (e EFIDevicePath) Format() string {
	return "No format"
}

func ParseDevicePath(f io.Reader) ([]EFIDevicePaths, error) {
	var ret []EFIDevicePaths
	for {
		var efidevice EFIDevicePath
		if err := binary.Read(f, binary.LittleEndian, &efidevice); err != nil {
			log.Fatalf("Failed to parse EFI Device Path: %s", err)
		}
		switch efidevice.Type {
		case Hardware:
			d := ParseHardwareDevicePath(f, &efidevice)
			ret = append(ret, d)
		case ACPI:
			d := ParseACPIDevicePath(f, &efidevice)
			ret = append(ret, d)
		case MediaDevicePath:
			d, err := ParseMediaDevicePath(f, &efidevice)
			if err != nil {
				return nil, err
			}
			ret = append(ret, d)
		case MessagingDevicePath:
			d := ParseMessagingDevicePath(f, &efidevice)
			ret = append(ret, d)
		case EndOfHardwareDevicePath:
			// log.Printf("Reached end of HardwareDevicePath: %+v\n", efidevice)
			goto end
		default:
			// log.Printf("Not implemented EFIDevicePath type: %+v\n", efidevice)
			goto end
		}
	}
end:
	return ret, nil
}

func ParseEFILoadOption(f *bytes.Buffer) (*EFILoadOption, error) {
	var bootentry EFILoadOption
	for _, b := range []interface{}{&bootentry.Attributes, &bootentry.FilePathListLength} {
		if err := binary.Read(f, binary.LittleEndian, b); err != nil {
			return nil, fmt.Errorf("can't parse EFI Load Option: %w", err)
		}
	}

	b := util.ReadNullString(f)
	s, err := util.ParseUtf16Var(bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	bootentry.Description = s
	return &bootentry, nil
}
