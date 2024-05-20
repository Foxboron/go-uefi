package util

import (
	"bytes"
	"errors"
	"io"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// Read a null terminated string
func ReadNullString(f io.Reader) []byte {
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

func MarshalUtf16Var(s string) []byte {
	var b bytes.Buffer
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	utf16Writer := transform.NewWriter(&b, utf16.NewEncoder())
	utf16Writer.Write([]byte(s))
	utf16Writer.Write([]byte("\x00"))
	return b.Bytes()
}

// Parse an efivar as a UTF-16 string.
func ParseUtf16Var(data *bytes.Buffer) (string, error) {
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	utf16Reader := transform.NewReader(data, utf16.NewDecoder())
	b, err := io.ReadAll(utf16Reader)

	if err != nil {
		return "", err
	}

	if b[len(b)-1] != 0 {
		return "", errors.New("value is not a null-terminated string")
	}

	return string(bytes.Trim(b, "\x00")), nil
}
