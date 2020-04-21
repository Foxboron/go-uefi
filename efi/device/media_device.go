package device

import (
	"bytes"
	"encoding/binary"
	"log"

	"github.com/foxboron/goefi/efi/util"
)

// Subtypes of Media Device
// Section 10.3.5 - Media Device Path
const (
	_ DevicePathSubType = iota
	HardDriveMediaDevice
	CDRomMediaDevice
	_
	FileTypeMediaDevice
)

type HardDriveMediaDevicePath struct {
	EFIDevicePath
	PartitionNumber    [4]byte
	PartitionStart     [8]byte
	PartitionSize      [8]byte
	PartitionSignature [16]byte
	PartitionFormat    [1]byte
	SignatureType      [1]byte
}

type FileTypeMediaDevicePath struct {
	EFIDevicePath
	PathName []byte
}

func ParseMediaDevicePath(f *bytes.Reader, efi *EFIDevicePath) EFILoadOptions {
	switch efi.SubType {
	case HardDriveMediaDevice:
		m := HardDriveMediaDevicePath{EFIDevicePath: *efi}
		// var m HardDriveMediaDevicePath
		if err := binary.Read(f, binary.LittleEndian, &m.PartitionNumber); err != nil {
			log.Fatal(err)
		}
		if err := binary.Read(f, binary.LittleEndian, &m.PartitionStart); err != nil {
			log.Fatal(err)
		}
		if err := binary.Read(f, binary.LittleEndian, &m.PartitionSize); err != nil {
			log.Fatal(err)
		}
		if err := binary.Read(f, binary.LittleEndian, &m.PartitionSignature); err != nil {
			log.Fatal(err)
		}
		if err := binary.Read(f, binary.LittleEndian, &m.PartitionFormat); err != nil {
			log.Fatal(err)
		}
		if err := binary.Read(f, binary.LittleEndian, &m.SignatureType); err != nil {
			log.Fatal(err)
		}
		return m
	case FileTypeMediaDevice:
		file := FileTypeMediaDevicePath{EFIDevicePath: *efi}
		file.PathName = util.ReadNullString(f)
		return file
	default:
		log.Fatalf("Not implemented EFIDevicePath type: %x", efi.SubType)
	}
	return nil
}
