package util

import (
	"bytes"
	"encoding/asn1"
)

// Read a null terminated string
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
