// +build integrations

package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
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

func TestEnrollKeys(t *testing.T) {
	PKKey, _ := os.ReadFile("/mnt/PK.key")
	PKPem, _ := os.ReadFile("/mnt/PK.pem")
	KEKKey, _ := os.ReadFile("/mnt/KEK.key")
	KEKPem, _ := os.ReadFile("/mnt/KEK.pem")
	dbPem, _ := os.ReadFile("/mnt/db.pem")
	if err := Enroll(dbPem, KEKKey, KEKPem, "db"); err != nil {
		t.Fatal(err)
	}
	if err := Enroll(KEKPem, PKKey, PKPem, "KEK"); err != nil {
		t.Fatal(err)
	}
	if err := Enroll(PKPem, PKKey, PKPem, "PK"); err != nil {
		t.Fatal(err)
	}
}
