package util

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Defined two places

// Section 7.3 - Protocol Handler Services
// Related Definitions
// Page 176

// Appendix A - GUID and Time Formats
// Page 2272

type EFIGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]uint8
}

const SizeofEFIGUID uint32 = 16

// Pretty print an EFIGUID struct
func (e *EFIGUID) Format() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x", e.Data1, e.Data2, e.Data3, e.Data4[:2], e.Data4[2:])
}

func (e *EFIGUID) Bytes() []byte {
	return GUIDToBytes(e)
}

// Compare two EFIGUID structs
func CmpEFIGUID(cmp1 EFIGUID, cmp2 EFIGUID) bool {
	return cmp1.Data1 == cmp2.Data1 &&
		cmp1.Data2 == cmp2.Data2 &&
		cmp1.Data3 == cmp2.Data3 &&
		cmp1.Data4 == cmp2.Data4
}

// Convert a string to an EFIGUID
func StringToGUID(s string) *EFIGUID {
	decoded, _ := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return BytesToGUID(decoded)
}

// Convert a byte slice to an EFIGUID
func BytesToGUID(s []byte) *EFIGUID {
	var efi EFIGUID
	f := bytes.NewReader(s[:])
	binary.Read(f, binary.BigEndian, &efi)
	return &efi
}

// Convert an EFIGUID to a byte slice
func GUIDToBytes(g *EFIGUID) []byte {
	b := new(bytes.Buffer)
	for _, v := range []interface{}{g.Data1, g.Data2, g.Data3, g.Data4} {
		binary.Write(b, binary.BigEndian, v)
	}
	return b.Bytes()
}

// Write an EFIGUID to a bytes.Buffer
func WriteGUID(b *bytes.Buffer, g *EFIGUID) {
	for _, v := range []interface{}{g.Data1, g.Data2, g.Data3, g.Data4} {
		binary.Write(b, binary.BigEndian, v)
	}
}
