package efivarfs

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"fmt"

	"github.com/foxboron/go-uefi/efi/device"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efivar"
)

// This is the high-level abstraction of efivarfs. It gives you the easy
// variable access and auxillary functions you should expect from a library like
// this.

type Efivarfs struct {
	EFIVars
}

func Open(e EFIVars) *Efivarfs {
	return &Efivarfs{e}
}

func (e *Efivarfs) GetPK() (*signature.SignatureDatabase, error) {
	var rsb signature.SignatureDatabase
	if err := e.GetVar(efivar.PK, &rsb); err != nil {
		return nil, err
	}
	return &rsb, nil
}

func (e *Efivarfs) GetSetupMode() (bool, error) {
	var rsb efibool
	if err := e.GetVar(efivar.SetupMode, &rsb); err != nil {
		return false, err
	}
	return (bool)(rsb), nil
}

func (e *Efivarfs) GetSecureBoot() (bool, error) {
	var rsb efibool
	if err := e.GetVar(efivar.SecureBoot, &rsb); err != nil {
		return false, err
	}
	return (bool)(rsb), nil
}

func (e *Efivarfs) GetKEK() (*signature.SignatureDatabase, error) {
	var rsb signature.SignatureDatabase
	if err := e.GetVar(efivar.KEK, &rsb); err != nil {
		return nil, err
	}
	return &rsb, nil
}

func (e *Efivarfs) Getdb() (*signature.SignatureDatabase, error) {
	var rsb signature.SignatureDatabase
	if err := e.GetVar(efivar.Db, &rsb); err != nil {
		return nil, err
	}
	return &rsb, nil
}

func (e *Efivarfs) Getdbx() (*signature.SignatureDatabase, error) {
	var rsb signature.SignatureDatabase
	if err := e.GetVar(efivar.Dbx, &rsb); err != nil {
		return nil, err
	}
	return &rsb, nil
}

// Writes a signed variable update
func (e *Efivarfs) WriteSignedUpdate(v efivar.Efivar, m efivar.Marshallable, key crypto.Signer, cert *x509.Certificate) error {
	// The reason why we do this is because we are wrapping a bytes.Butter in a
	// marshaller interface to pass through the layers
	// I haven't decided if this is.. elegant or not.
	_, marshal, err := signature.SignEFIVariable(v, m, key, cert)
	if err != nil {
		return err
	}

	return e.WriteVar(v, marshal)
}

func (e *Efivarfs) GetBootEntry(option string) (*device.EFILoadOption, error) {
	var rsb device.EFILoadOption
	entry := efivar.BootEntry
	entry.Name = option
	if err := e.GetVar(entry, &rsb); err != nil {
		return nil, err
	}
	return &rsb, nil
}

type bootorder []string

func (bo *bootorder) Unmarshal(b *bytes.Buffer) error {
	for i := 0; b.Len() != 0; i += 2 {
		sec := make([]byte, 2)
		b.Read(sec)
		val := binary.BigEndian.Uint16([]byte{sec[1], sec[0]})
		*bo = append(*bo, fmt.Sprintf("Boot%04x", val))
	}
	return nil
}

func (e *Efivarfs) GetBootOrder() []string {
	var rsb bootorder
	if err := e.GetVar(efivar.BootOrder, &rsb); err != nil {
		return nil
	}
	return rsb
}
