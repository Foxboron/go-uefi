package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/tests/utils"
)

var TestGUID = util.EFIGUID{0xa7717414, 0xc616, 0x4977, [8]uint8{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}}

func Enroll(cert, signerKey, signerPem []byte, efivar string) error {
	c := signature.NewSignatureList(signature.CERT_X509_GUID)
	c.AppendBytes(TestGUID, cert)
	buf := new(bytes.Buffer)
	signature.WriteSignatureList(buf, *c)
	signedBuf := efi.SignEFIVariable(util.ReadKey(signerKey), util.ReadCert(signerPem), efivar, buf.Bytes())
	return efi.WriteEFIVariable(efivar, signedBuf)
}

func TestRemovePK(t *testing.T) {
	PKKey, _ := os.ReadFile("/mnt/PK.key")
	PKPem, _ := os.ReadFile("/mnt/PK.pem")

	signedBuf := efi.SignEFIVariable(util.ReadKey(PKKey), util.ReadCert(PKPem), "PK", []byte{})
	if err := efi.WriteEFIVariable("PK", signedBuf); err != nil {
		t.Fatal(err)
	}
	if !efi.GetSecureBoot() {
		t.Fatal("Not in secure boot mode")
	}

	if !efi.GetSetupMode() {
		t.Fatal("Not in setup mode")
	}
	if err := Enroll(PKPem, PKKey, PKPem, "PK"); err != nil {
		t.Fatal(err)
	}

	if efi.GetSetupMode() {
		t.Fatal("Still in setup mode")
	}
}

func TestRotateKeys(t *testing.T) {
	PKKey, PKPem := utils.CreateKey()
	PKKeyOld, _ := os.ReadFile("/mnt/PK.key")
	PKPemOld, _ := os.ReadFile("/mnt/PK.pem")
	KEKPemOld, _ := os.ReadFile("/mnt/KEK.pem")
	_, KEKPem := utils.CreateKey()
	_, dbPem := utils.CreateKey()

	// For rotating keys we need to go from the classic enrollment
	// db -> KEK -> PK
	// To
	// KEK -> db -> PK
	// Where all the new keys are signed by the old Platform key

	if err := Enroll(KEKPem, PKKeyOld, PKPemOld, "KEK"); err != nil {
		t.Fatal(err)
	}
	if err := Enroll(dbPem, PKKeyOld, PKPemOld, "db"); err != nil {
		t.Fatal(err)
	}
	if err := Enroll(PKPem, PKKeyOld, PKPemOld, "PK"); err != nil {
		t.Fatal(err)
	}
	if efi.GetSetupMode() {
		t.Fatal("Still in setup mode")
	}

	// Enroll back the old KEK for the next test
	if err := Enroll(KEKPemOld, PKKey, PKPem, "KEK"); err != nil {
		t.Fatal(err)
	}
}
