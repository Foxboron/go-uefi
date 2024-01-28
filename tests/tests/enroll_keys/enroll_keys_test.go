package main

import (
	"os"
	"testing"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/efivar"
	"github.com/foxboron/go-uefi/efivarfs"
	"github.com/hugelgupf/vmtest/guest"
)

func TestSecureBootDisabled(t *testing.T) {
	guest.SkipIfNotInVM(t)

	if efi.GetSecureBoot() {
		t.Fatal("in secure boot mode")
	}

	if !efi.GetSetupMode() {
		t.Fatal("not in setup mode")
	}
}

var TestGUID = util.EFIGUID{0xa7717414, 0xc616, 0x4977, [8]uint8{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}}

func Enroll(efifs *efivarfs.Efivarfs, cert, signerKey, signerPem []byte, efivar efivar.Efivar) error {
	c := signature.NewSignatureDatabase()
	c.AppendSignature(signature.CERT_X509_GUID, &signature.SignatureData{Owner: TestGUID, Data: cert})
	key, _ := util.ReadKey(signerKey)
	pem, _ := util.ReadCert(signerPem)
	return efifs.WriteSignedUpdate(efivar, c, key, pem)
}

func TestEnrollKeys(t *testing.T) {
	guest.SkipIfNotInVM(t)

	PKKey, _ := os.ReadFile("/testdata/PK/PK.key")
	PKPem, _ := os.ReadFile("/testdata/PK/PK.pem")
	KEKKey, _ := os.ReadFile("/testdata/KEK/KEK.key")
	KEKPem, _ := os.ReadFile("/testdata/KEK/KEK.pem")
	dbPem, _ := os.ReadFile("/testdata/db/db.pem")

	efifs := efivarfs.NewFS().
		CheckImmutable().
		UnsetImmutable().
		Open()

	if err := Enroll(efifs, dbPem, KEKKey, KEKPem, efivar.Db); err != nil {
		t.Fatal(err)
	}
	if err := Enroll(efifs, KEKPem, PKKey, PKPem, efivar.KEK); err != nil {
		t.Fatal(err)
	}
	if err := Enroll(efifs, PKPem, PKKey, PKPem, efivar.PK); err != nil {
		t.Fatal(err)
	}
}

func TestOutOfSetupMode(t *testing.T) {
	guest.SkipIfNotInVM(t)

	if efi.GetSetupMode() {
		t.Fatal("still inside setup mode")
	}

	if efi.GetSecureBoot() {
		t.Fatal("in secure boot mode")
	}
}
