package main

import (
	"crypto"
	"crypto/x509"
	"os"
	"testing"

	"github.com/foxboron/go-uefi/asntest"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/efivar"
	"github.com/foxboron/go-uefi/efivarfs"
	"github.com/hugelgupf/vmtest/guest"
)

var TestGUID = util.EFIGUID{0xa7717414, 0xc616, 0x4977, [8]uint8{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}}

func Enroll(efifs *efivarfs.Efivarfs, cert *x509.Certificate, signerKey crypto.Signer, signerPem *x509.Certificate, efivar efivar.Efivar) error {
	c := signature.NewSignatureDatabase()
	c.AppendSignature(signature.CERT_X509_GUID, &signature.SignatureData{Owner: TestGUID, Data: asntest.CertToBytes(cert)})
	return efifs.WriteSignedUpdate(efivar, c, signerKey, signerPem)
}

func TestRemovePK(t *testing.T) {
	guest.SkipIfNotInVM(t)

	PKKey, _ := os.ReadFile("/testdata/PK/PK.key")
	PKPem, _ := os.ReadFile("/testdata/PK/PK.pem")
	readKey, _ := util.ReadKey(PKKey)
	readCert, _ := util.ReadCert(PKPem)

	efifs := efivarfs.NewFS().
		CheckImmutable().
		UnsetImmutable().
		Open()

	wsb := signature.NewSignatureDatabase()
	err := efifs.WriteSignedUpdate(efivar.PK, wsb, readKey, readCert)
	if err != nil {
		t.Error(err)
	}

	if ok, _ := efifs.GetSecureBoot(); !ok {
		t.Fatal("Not in secure boot mode")
	}

	if ok, _ := efifs.GetSetupMode(); !ok {
		t.Fatal("Not in setup mode")
	}
	if err := Enroll(efifs, readCert, readKey, readCert, efivar.PK); err != nil {
		t.Fatal(err)
	}

	if ok, _ := efifs.GetSetupMode(); ok {
		t.Fatal("Still in setup mode")
	}
}

func TestRotateKeys(t *testing.T) {
	guest.SkipIfNotInVM(t)

	PKKeyOld, _ := os.ReadFile("/testdata/PK/PK.key")
	PKPemOld, _ := os.ReadFile("/testdata/PK/PK.pem")

	// New Keys
	PKPem, _ := asntest.InitCert()
	KEKPem, _ := asntest.InitCert()
	dbPem, _ := asntest.InitCert()

	PKKeyOldK, _ := util.ReadKey(PKKeyOld)
	PKPemOldK, _ := util.ReadCert(PKPemOld)

	efifs := efivarfs.NewFS().
		CheckImmutable().
		UnsetImmutable().
		Open()

	// For rotating keys we need to go from the classic enrollment
	// db -> KEK -> PK
	// To
	// KEK -> db -> PK
	// Where all the new keys are signed by the old Platform key

	if err := Enroll(efifs, KEKPem, PKKeyOldK, PKPemOldK, efivar.KEK); err != nil {
		t.Fatalf("failed KEK enroll: %v", err)
	}
	if err := Enroll(efifs, dbPem, PKKeyOldK, PKPemOldK, efivar.Db); err != nil {
		t.Fatalf("failed db enroll: %v", err)
	}
	if err := Enroll(efifs, PKPem, PKKeyOldK, PKPemOldK, efivar.PK); err != nil {
		t.Fatalf("failed PK enroll: %v", err)
	}
	if ok, _ := efifs.GetSetupMode(); ok {
		t.Fatal("Still in setup mode")
	}
}
