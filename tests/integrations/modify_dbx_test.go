//go:build integrations
// +build integrations

package main

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/attributes"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
)

var sigdata = []signature.SignatureData{
	signature.SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x81, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
	signature.SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x82, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
	signature.SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x83, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
}

var (
	Key, _  = util.ReadKeyFromFile("/mnt/KEK.key")
	Cert, _ = util.ReadCertFromFile("/mnt/KEK.pem")
)

func ReadKeyDB(vars string) (signature.SignatureDatabase, error) {
	_, f, err := attributes.ReadEfivars(vars)
	if err != nil {
		return nil, err
	}
	sigdb, err := signature.ReadSignatureDatabase(f)
	if err != nil {
		return nil, err
	}
	return sigdb, nil
}

func TestRemoveRewritedbx(t *testing.T) {
	sl := signature.NewSignatureList(signature.CERT_SHA256_GUID)
	for _, sig := range sigdata {
		sl.AppendBytes(sig.Owner, sig.Data)
		buf := new(bytes.Buffer)
		signature.WriteSignatureList(buf, *sl)
		signedBuf, err := efi.SignEFIVariable(Key, Cert, "dbx", buf.Bytes())
		if err != nil {
			t.Error(err)
		}
		if err := efi.WriteEFIVariable("dbx", signedBuf); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
	}

	sigdb, err := ReadKeyDB("dbx")
	if err != nil {
		t.Fatal(err)
	}
	if len(sigdb) != 1 {
		t.Fatal("sigdb does not have one list")
	}
	if len(sigdb[0].Signatures) != 3 {
		t.Fatal("signature list does not have 3 signatures")
	}
}

func TestRemoveDBX(t *testing.T) {
	signedBuf, err := efi.SignEFIVariable(Key, Cert, "dbx", []byte{})
	if err != nil {
		t.Fatal(err)
	}
	if err := efi.WriteEFIVariable("dbx", signedBuf); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyDB("dbx"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
