package util

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
)

func ReadNullString(f *bytes.Reader) []byte {
	var ret []byte
	for {
		block := make([]byte, 2)
		r, _ := f.Read(block)
		if r == 0 {
			break
		}
		ret = append(ret, block...)
		if bytes.Equal(block, []byte{0x00, 0x00}) {
			break
		}
	}
	return ret
}

type EFIGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]uint8
}

func (e *EFIGUID) Format() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", e.Data1, e.Data2, e.Data3, e.Data4[:2], e.Data4[2:])
}

func CmpEFIGUID(cmp1 EFIGUID, cmp2 EFIGUID) bool {
	return cmp1.Data1 == cmp2.Data1 &&
		cmp1.Data2 == cmp2.Data2 &&
		cmp1.Data3 == cmp2.Data3 &&
		cmp1.Data4 == cmp2.Data4
}

func StringToGUID(s string) *EFIGUID {
	decoded, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil {
		log.Fatal(err)
	}
	return BytesToGUID(decoded)
}

func BytesToGUID(s []byte) *EFIGUID {
	var efi EFIGUID
	f := bytes.NewReader(s[:])
	if err := binary.Read(f, binary.BigEndian, &efi); err != nil {
		log.Fatal(err)
	}
	return &efi
}

func GUIDToBytes(g *EFIGUID) []byte {
	b := new(bytes.Buffer)
	for _, v := range []interface{}{g.Data1, g.Data2, g.Data3, g.Data4} {
		err := binary.Write(b, binary.BigEndian, v)
		if err != nil {
			log.Fatal(err)
		}
	}
	return b.Bytes()
}

func WriteGUID(b *bytes.Buffer, g *EFIGUID) {
	for _, v := range []interface{}{g.Data1, g.Data2, g.Data3, g.Data4} {
		err := binary.Write(b, binary.BigEndian, v)
		if err != nil {
			log.Fatal(err)
		}
	}
}
