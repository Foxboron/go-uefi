package efivarfs

import (
	"reflect"
	"testing"

	"github.com/foxboron/go-uefi/asntest"
	"github.com/foxboron/go-uefi/efi/efitest"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/efivar"
)

var (
	sigdata = []signature.SignatureData{
		signature.SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x81, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
		signature.SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x82, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
		signature.SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x83, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
	}
)

func TestGetSecureBootEfivar(t *testing.T) {
	efivarfs := NewTestFS().
		With(efitest.SetUpModeOff()).
		Open()
	ok, err := efivarfs.GetSetupMode()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if ok != true {
		t.Fatalf("wrong")
	}
}

func TestWriteSignatureDatabaseEfivar(t *testing.T) {
	efivarfs := NewTestFS().Open()

	// Write some test data
	var wsb signature.SignatureDatabase
	for _, sig := range sigdata {
		wsb.AppendSignature(signature.CERT_SHA256_GUID, &sig)
	}

	if err := efivarfs.WriteVar(efivar.Db, &wsb); err != nil {
		t.Fatalf("encountered error: %v", err)
	}

	var rsb signature.SignatureDatabase
	if err := efivarfs.GetVar(efivar.Db, &rsb); err != nil {
		t.Fatalf("encountered error: %v", err)
	}

	if !reflect.DeepEqual(wsb[0].Signatures, rsb[0].Signatures) {
		t.Fatalf("Not equal")
	}
}

func TestWriteSignatureDatabaseEfivarAuthedUpdate(t *testing.T) {
	efivarfs := NewTestFS().Open()

	cert, priv := asntest.InitCert()

	// Write some test data
	var wsb signature.SignatureDatabase
	for _, sig := range sigdata {
		wsb.AppendSignature(signature.CERT_SHA256_GUID, &sig)
	}

	err := efivarfs.WriteSignedUpdate(efivar.Db, &wsb, priv, cert)
	if err != nil {
		t.Fatal(err)
	}

	rsb, err := efivarfs.Getdb()
	if err != nil {
		t.Fatalf("encountered error: %v", err)
	}

	if !reflect.DeepEqual(wsb[0].Signatures, (*rsb)[0].Signatures) {
		t.Fatalf("Not equal")
	}
}
