package efivarfs

import (
	"crypto"
	"crypto/x509"

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
	_, marshal, err := signature.SignEFIVariable(efivar.Db, m, key, cert)
	if err != nil {
		return err
	}

	e.WriteVar(v, marshal)
	return nil
}
