package device

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"github.com/foxboron/go-uefi/efi/util"
)

// Subtypes of Media Device
// Section 10.3.5 - Media Device Path
const (
	_ DevicePathSubType = iota
	HardDriveDevicePath
	CDRomDevicePath
	VendorMediaDevicePath
	FilePathDevicePath
	MediaProtocolDevicePath
	PIWGFirmwareDevicePath
)

type HardDriveMediaDevicePath struct {
	EFIDevicePath
	PartitionNumber    uint32
	PartitionStart     [8]byte
	PartitionSize      [8]byte
	PartitionSignature [16]byte
	PartitionFormat    uint8
	SignatureType      uint8
}

func (h HardDriveMediaDevicePath) Format() string {
	format := []string{"MBR", "GPT"}
	if h.PartitionNumber == 0 {
		return fmt.Sprintf("HD(%d,%s,%x)",
			h.PartitionNumber,
			format[h.PartitionFormat-1],
			h.PartitionSignature)
	}
	return fmt.Sprintf("HD(%d,%s,%s,0x%x,0x%x)",
		h.PartitionNumber,
		format[h.PartitionFormat-1],
		util.BytesToGUID(h.PartitionSignature[:]).Format(),
		binary.LittleEndian.Uint64(h.PartitionStart[:]),
		binary.LittleEndian.Uint64(h.PartitionSize[:]))
}

type FileTypeMediaDevicePath struct {
	EFIDevicePath
	PathName string
}

func (f FileTypeMediaDevicePath) Format() string {
	return fmt.Sprintf("File(%s)", f.PathName)
}

type FirmwareFielMediaDevicePath struct {
	EFIDevicePath
	FirmwareFileName [16]byte
}

func (f FirmwareFielMediaDevicePath) Format() string {
	return "No format"
}

func ParseMediaDevicePath(f io.Reader, efi *EFIDevicePath) (EFIDevicePaths, error) {
	var err error
	switch efi.SubType {
	case HardDriveDevicePath:
		m := HardDriveMediaDevicePath{EFIDevicePath: *efi}
		for _, b := range []interface{}{
			&m.PartitionNumber,
			&m.PartitionStart,
			&m.PartitionSize,
			&m.PartitionSignature,
			&m.PartitionFormat,
			&m.SignatureType,
		} {
			if err := binary.Read(f, binary.LittleEndian, b); err != nil {
				return nil, fmt.Errorf("Couldn't parse Harddrive Device Path: %w", err)
			}
		}
		return m, nil
	case FilePathDevicePath:
		file := FileTypeMediaDevicePath{EFIDevicePath: *efi}
		b := util.ReadNullString(f)
		file.PathName, err = util.ParseUtf16Var(bytes.NewBuffer(b))
		if err != nil {
			return nil, err
		}
		return file, nil
	case PIWGFirmwareDevicePath:
		file := FirmwareFielMediaDevicePath{EFIDevicePath: *efi}
		if err := binary.Read(f, binary.LittleEndian, &file.FirmwareFileName); err != nil {
			return nil, fmt.Errorf("Couldn't parse PIWG Firmware Device Path: %w", err)
		}
		return file, nil
	default:
		log.Printf("Not implemented MediaDevicePath type: %x", efi.SubType)
	}
	return nil, nil
}
