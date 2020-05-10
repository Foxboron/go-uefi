package attributes

import (
	"encoding/binary"
	"fmt"
	"os"
	"path"

	"github.com/foxboron/goefi/efi/util"
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

var Efivars = "/sys/firmware/efi/efivars"

type EfiVariable struct {
	Attributes Attributes
	Data       []byte
}

func ParseEfivars(f *os.File) (*EfiVariable, error) {
	var variable EfiVariable
	if err := binary.Read(f, binary.LittleEndian, &variable.Attributes); err != nil {
		return &EfiVariable{}, nil
	}
	stat, err := f.Stat()
	if err != nil {
		return &EfiVariable{}, nil
	}
	buf := make([]byte, stat.Size()-4)
	if err = binary.Read(f, binary.LittleEndian, &buf); err != nil {
		return &EfiVariable{}, nil
	}
	variable.Data = buf
	return &variable, nil
}

func ReadEfivars(filename string) (*EfiVariable, error) {
	f, err := os.Open(path.Join(Efivars, fmt.Sprintf("%s-%s", filename, EFI_GLOBAL_VARIABLE.Format())))
	if err != nil {
		return &EfiVariable{}, nil
	}
	return ParseEfivars(f)
}

// For a full path instead of the inferred efivars path
func ReadEfivarsFile(filename string) (*EfiVariable, error) {
	f, err := os.Open(filename)
	if err != nil {
		return &EfiVariable{}, err
	}
	return ParseEfivars(f)
}
