package efivarfs

import (
	"bytes"
	"io"
)

// This package contains misc types we might promote to something more sane at a later point.
// Currently only used internally to serialize/deserialize values we need to native Go types.

// TODO: Move this to something better?
//
//	I don't think we'll be using this to actually write stuff
type efibool bool

func (s *efibool) Unmarshal(b *bytes.Buffer) error {
	n, err := b.ReadByte()
	if err != nil {
		return err
	}
	*s = n == 1
	return nil
}

type efibytes bytes.Buffer

func (e efibytes) Marshal(b *bytes.Buffer) {
	if _, err := io.Copy(b, (*bytes.Buffer)(&e)); err != nil {
		return
	}
}

func (e efibytes) Bytes() []byte {
	var b bytes.Buffer
	e.Marshal(&b)
	return b.Bytes()
}
