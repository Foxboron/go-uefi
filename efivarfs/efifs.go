package efivarfs

import (
	"bytes"
	"errors"

	"github.com/foxboron/go-uefi/efi/attr"
	"github.com/foxboron/go-uefi/efi/attributes"
	"github.com/foxboron/go-uefi/efivar"
	"github.com/foxboron/go-uefi/efivarfs/fswrapper"
)

// This package deals with the interface actually writing the variables properly
// to the efivarfs backend.

var (
	ErrImmutable           = attr.ErrIsImmutable
	ErrIncorrectAttributes = errors.New("efivar has the wrong attributes")
)

// EFIVars is the interface for interacting with writing and getting EFI variables.
type EFIVars interface {
	GetVar(efivar.Efivar, efivar.Unmarshallable) error
	GetVarWithAttributes(efivar.Efivar, efivar.Unmarshallable) (attributes.Attributes, error)
	WriteVar(efivar.Efivar, efivar.Marshallable) error
}

// EFIFS is a struct that combines reading variables from the file system while also ensuring we are
type EFIFS struct {
	*fswrapper.FSWrapper
}

var _ EFIVars = &EFIFS{}

// NewFS creates a new instance of *EFIFS
func NewFS() *EFIFS {
	return &EFIFS{
		fswrapper.NewFSWrapper(),
	}
}

// Open returns a initialization Efivarfs for high-level abstractions.
func (f *EFIFS) Open() *Efivarfs {
	return &Efivarfs{f}
}

// Check if file is immutable before writing to the file.
// Returns ErrImmutable if the file is immutable.
func (f *EFIFS) CheckImmutable() *EFIFS {
	f.FSWrapper.CheckImmutable()
	return f
}

// UnsetImmutable implicitly when writing towards a file.
func (f *EFIFS) UnsetImmutable() *EFIFS {
	f.FSWrapper.UnsetImmutable()
	return f
}

// GetVar parses and unmarshalls a EFI variable.
func (t *EFIFS) GetVar(v efivar.Efivar, e efivar.Unmarshallable) error {
	if _, err := t.GetVarWithAttributes(v, e); err != nil {
		return err
	}
	return nil
}

// GetVarWithAttributes parses and unmarshalls a EFI variable, while also
// returning the parsed attributes.
func (t *EFIFS) GetVarWithAttributes(v efivar.Efivar, e efivar.Unmarshallable) (attributes.Attributes, error) {
	attrs, buf, err := t.ReadEfivarsWithGuid(v.Name, *v.GUID)
	if err != nil {
		return 0, err
	}

	if !v.Attributes.Equal(attrs) {
		return attrs, ErrIncorrectAttributes
	}

	if err := e.Unmarshal(buf); err != nil {
		return 0, err
	}

	return attrs, nil
}

// WriteVar writes an EFI variables to the EFIFS.
func (t *EFIFS) WriteVar(v efivar.Efivar, e efivar.Marshallable) error {
	var b bytes.Buffer
	e.Marshal(&b)
	return t.WriteEfivarsWithGuid(v.Name, v.Attributes, b.Bytes(), *v.GUID)
}
