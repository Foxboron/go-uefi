package main

import (
	"bytes"
	"testing"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/tests/utils"
)

var TestGUID = util.EFIGUID{0xa7717414, 0xc616, 0x4977, [8]uint8{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}}

func TestEnrollKeys(t *testing.T) {
	PKKey, PKPem := utils.CreateKey()
	KEKKey, KEKPem := utils.CreateKey()
	_, dbPem := utils.CreateKey()

	c := signature.NewSignatureList(dbPem, TestGUID, signature.CERT_X509)
	buf := new(bytes.Buffer)
	signature.WriteSignatureList(buf, *c)
	signedBuf := efi.SignEFIVariable(util.ReadKey(KEKKey), util.ReadCert(KEKPem), "db", buf.Bytes())
	if err := efi.WriteEFIVariable("db", signedBuf); err != nil {
		t.Fatal(err)
	}
	c = signature.NewSignatureList(KEKPem, TestGUID, signature.CERT_X509)
	buf = new(bytes.Buffer)
	signature.WriteSignatureList(buf, *c)
	signedBuf = efi.SignEFIVariable(util.ReadKey(PKKey), util.ReadCert(PKPem), "KEK", buf.Bytes())
	if err := efi.WriteEFIVariable("KEK", signedBuf); err != nil {
		t.Fatal(err)
	}
	c = signature.NewSignatureList(PKPem, TestGUID, signature.CERT_X509)
	buf = new(bytes.Buffer)
	signature.WriteSignatureList(buf, *c)
	signedBuf = efi.SignEFIVariable(util.ReadKey(PKKey), util.ReadCert(PKPem), "PK", buf.Bytes())
	if err := efi.WriteEFIVariable("PK", signedBuf); err != nil {
		t.Fatal(err)
	}
}
