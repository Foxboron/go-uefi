package attributes

import (
	"encoding/binary"
	"fmt"
	"os"
	"path"
)

type Attributes uint32

const (
	EFI_VARIABLE_NON_VOLATILE                          Attributes = 0x00000001
	EFI_VARIABLE_BOOTSERVICE_ACCESS                               = 0x00000002
	EFI_VARIABLE_RUNTIME_ACCESS                                   = 0x00000004
	EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS            = 0x00000020
	EFI_VARIABLE_APPEND_WRITE                                     = 0x00000040
)

const GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

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
	f, err := os.Open(path.Join(Efivars, fmt.Sprintf("%s-%s", filename, GUID)))
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
