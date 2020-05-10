package efi

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/foxboron/goefi/efi/attributes"
	"github.com/foxboron/goefi/efi/device"
)

func GetBoorOrder() []string {
	ret := []string{}
	s, _ := attributes.ReadEfivars("BootOrder")
	for i := 0; i < len(s.Data); i += 2 {
		val := binary.BigEndian.Uint16([]byte{s.Data[i+1], s.Data[i]})
		ret = append(ret, fmt.Sprintf("Boot%04x\n", val))
	}
	return ret
}

func GetBootEntry(entry string) {
	s, _ := attributes.ReadEfivars(entry)
	f := bytes.NewReader(s.Data)
	_ = device.ParseEFILoadOption(f)
	_ = device.ParseDevicePath(f)
}

func GetSetupMode() []byte {
	attributes.ReadEfivars("SetupMode")
	attributes.ReadEfivars("PK")
	attributes.ReadEfivars("BootOrder")
	return []byte{}
}
