package main

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/efivar"
	"github.com/foxboron/go-uefi/efivarfs"
	"github.com/hugelgupf/vmtest/guest"
)

var sigdata = []signature.SignatureData{
	signature.SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x81, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
	signature.SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x82, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
	signature.SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x83, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
}

var (
	key, _  = util.ReadKeyFromFile("/testdata/KEK/KEK.key")
	cert, _ = util.ReadCertFromFile("/testdata/KEK/KEK.pem")
)

func TestRemoveRewritedbx(t *testing.T) {
	guest.SkipIfNotInVM(t)

	efifs := efivarfs.NewFS().
		CheckImmutable().
		UnsetImmutable().
		Open()

	wsb := signature.NewSignatureDatabase()
	for _, sig := range sigdata {
		wsb.AppendSignature(signature.CERT_SHA256_GUID, &sig)

		err := efifs.WriteSignedUpdate(efivar.Dbx, wsb, key, cert)
		if err != nil {
			t.Error(err)
		}
		time.Sleep(2 * time.Second)
	}

	var sigdb signature.SignatureDatabase
	if err := efifs.GetVar(efivar.Dbx, &sigdb); err != nil {
		t.Fatalf("failed reading dbx: %v", err)
	}

	if len(sigdb) != 1 {
		t.Fatal("sigdb does not have one list")
	}
	if len(sigdb[0].Signatures) != 3 {
		t.Fatal("signature list does not have 3 signatures")
	}
}

func TestRemoveDBX(t *testing.T) {
	guest.SkipIfNotInVM(t)

	efifs := efivarfs.NewFS().
		CheckImmutable().
		UnsetImmutable().
		Open()

	// Write empty signature database
	wsb := signature.NewSignatureDatabase()
	err := efifs.WriteSignedUpdate(efivar.Dbx, wsb, key, cert)
	if err != nil {
		t.Error(err)
	}

	var sigdb signature.SignatureDatabase
	if err := efifs.GetVar(efivar.Dbx, &sigdb); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("should return os.ErrNotExist, returned: %v", err)
	}
}
