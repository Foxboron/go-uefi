package attributes

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path"

	"github.com/pkg/errors"

	"github.com/foxboron/go-uefi/efi/attr"
	"github.com/foxboron/go-uefi/efi/util"
)

// Section 8.2 Variable Services
type Attributes uint32

const (
	EFI_VARIABLE_NON_VOLATILE                          Attributes = 0x00000001
	EFI_VARIABLE_BOOTSERVICE_ACCESS                    Attributes = 0x00000002
	EFI_VARIABLE_RUNTIME_ACCESS                        Attributes = 0x00000004
	EFI_VARIABLE_HARDWARE_ERROR_RECORD                 Attributes = 0x00000008
	EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS            Attributes = 0x00000010 // Deprecated, we only reserve it
	EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS Attributes = 0x00000020
	EFI_VARIABLE_APPEND_WRITE                          Attributes = 0x00000040
	EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS         Attributes = 0x00000080 // Uses the EFI_VARIABLE_AUTHENTICATION_3 struct
)

// NV -> Non-Volatile
// BS -> Boot Services
// RT -> Runtime Services
// AT -> Time Based Authenticated Write Access

var EFI_GLOBAL_VARIABLE = util.EFIGUID{0x8BE4DF61, 0x93CA, 0x11d2, [8]uint8{0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C}}

// Section 32.6 - Code Definition
// Section 32.6.1 - UEFI Variable GUID & Variable Name
// page 1728

// Valid Databases
// db  - authorized signature database
// dbx - forbidden signature database
// dbt - authorized timestamp signature database
// dbr - authorized recovery signature database
var (
	EFI_IMAGE_SECURITY_DATABASE_GUID = util.EFIGUID{0xd719b2cb, 0x3d3a, 0x4596, [8]uint8{0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f}}
	IMAGE_SECURITY_DATABASE          = "db"
	IMAGE_SECURITY_DATABASE1         = "dbx"
	IMAGE_SECURITY_DATABASE2         = "dbt"
	IMAGE_SECURITY_DATABASE3         = "dbr"
	ImageSecurityDatabases           = map[string]bool{
		IMAGE_SECURITY_DATABASE:  true,
		IMAGE_SECURITY_DATABASE1: true,
		IMAGE_SECURITY_DATABASE2: true,
		IMAGE_SECURITY_DATABASE3: true,
	}
)

var Efivars = "/sys/firmware/efi/efivars"

type EfiVariable struct {
	Attributes Attributes
	Data       []byte
}

func ParseEfivars(f *os.File) (Attributes, *bytes.Buffer, error) {
	var attrs Attributes
	if err := binary.Read(f, binary.LittleEndian, &attrs); err != nil {
		return 0, nil, errors.Wrap(err, "could not read file")
	}
	stat, err := f.Stat()
	if err != nil {
		return 0, nil, errors.Wrap(err, "could not stat file descriptor")
	}
	buf := make([]byte, stat.Size()-4)
	if err = binary.Read(f, binary.LittleEndian, &buf); err != nil {
		return 0, nil, err
	}
	return attrs, bytes.NewBuffer(buf), nil
}

func ReadEfivars(filename string) (Attributes, *bytes.Buffer, error) {
	guid := EFI_GLOBAL_VARIABLE
	if ok := ImageSecurityDatabases[filename]; ok {
		guid = EFI_IMAGE_SECURITY_DATABASE_GUID
	}
	return ReadEfivarsWithGuid(filename, guid)
}

func ReadEfivarsWithGuid(filename string, guid util.EFIGUID) (Attributes, *bytes.Buffer, error) {
	f, err := os.Open(path.Join(Efivars, fmt.Sprintf("%s-%s", filename, guid.Format())))
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	return ParseEfivars(f)
}

// For a full path instead of the inferred efivars path
func ReadEfivarsFile(filename string) (Attributes, *bytes.Buffer, error) {
	f, err := os.Open(filename)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	return ParseEfivars(f)
}

// Write an EFI variable to sysfs
func WriteEfivars(name string, attrs Attributes, b []byte) error {
	guid := EFI_GLOBAL_VARIABLE
	if ok := ImageSecurityDatabases[name]; ok {
		guid = EFI_IMAGE_SECURITY_DATABASE_GUID
	}
	// attrs |= EFI_VARIABLE_APPEND_WRITE
	efivar := path.Join(Efivars, fmt.Sprintf("%s-%s", name, guid.Format()))
	if err := attr.IsImmutable(efivar); errors.Is(err, attr.ErrIsImmutable) {
		err := attr.UnsetImmutable(efivar)
		if err != nil {
			return err
		}
	} else if errors.Is(err, os.ErrNotExist) {
	} else if err != nil {
		return err
	}

	f, err := os.OpenFile(efivar, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return errors.Wrap(err, "couldn't open file")
	}
	defer f.Close()
	attrBuf := new(bytes.Buffer)
	binary.Write(attrBuf, binary.LittleEndian, attrs)
	buf := append(attrBuf.Bytes(), b...)
	if n, err := f.Write(buf); err != nil {
		return errors.Wrap(err, "couldn't write efi variable")
	} else if n != len(buf) {
		return errors.New("could not write the entire buffer")
	}
	return nil
}
