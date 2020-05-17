package signature

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"testing"

	"github.com/foxboron/goefi/efi/attributes"
	"github.com/foxboron/goefi/efi/util"
	"go.mozilla.org/pkcs7"
)

func TestParseSignatureListVars(t *testing.T) {
	dir := "../../tests/data/signatures/efivars"
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		path := filepath.Join(dir, file.Name())
		s, _ := attributes.ReadEfivarsFile(path)
		var pkflags attributes.Attributes
		pkflags |= attributes.EFI_VARIABLE_NON_VOLATILE
		pkflags |= attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS
		pkflags |= attributes.EFI_VARIABLE_RUNTIME_ACCESS
		pkflags |= attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
		if (pkflags & s.Attributes) != pkflags {
			t.Errorf("Incorrect bitmask")
		}

		f := bytes.NewReader(s.Data)
		c := ReadSignatureList(f)
		if util.CmpEFIGUID(c.SignatureType, CERT_X509_GUID) {
			// Run over and ensure we are getting the correct type
			for _, d := range c.Signatures {
				_, err := pkcs7.NewSignedData(d.Data)
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

func TestParseSignatureListFile(t *testing.T) {
	dir := "../../tests/data/signatures/siglist"
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		path := filepath.Join(dir, file.Name())
		b, _ := ioutil.ReadFile(path)
		f := bytes.NewReader(b)
		c := ReadSignatureList(f)
		if util.CmpEFIGUID(c.SignatureType, CERT_X509_GUID) {
			// Run over and ensure we are getting the correct type
			for _, d := range c.Signatures {
				fmt.Println(file.Name())
				fmt.Println(d.Owner.Format())
				_, err := pkcs7.NewSignedData(d.Data)
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

func TestParseSignatureListHashFile(t *testing.T) {
	dir := "../../tests/data/signatures/siglistchecksum"
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		path := filepath.Join(dir, file.Name())
		b, _ := ioutil.ReadFile(path)
		f := bytes.NewReader(b)
		c := ReadSignatureList(f)
		if util.CmpEFIGUID(c.SignatureType, CERT_SHA256_GUID) {
			for _, d := range c.Signatures {
				if fmt.Sprintf("%x", d.Data) != "4be2e8d5ef8113c3b9218f05f8aed1df8a6b0e24c706360d39f74a7423f00e32" {
					log.Fatal("Not correct checksum")
				}
			}
		}
	}
}

func TestParseSignatureSupport(t *testing.T) {
	dir := "../../tests/data/signatures/sigsupport"

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		path := filepath.Join(dir, file.Name())
		s, _ := attributes.ReadEfivarsFile(path)

		var pkflags attributes.Attributes
		pkflags |= attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS
		pkflags |= attributes.EFI_VARIABLE_RUNTIME_ACCESS
		if (pkflags & s.Attributes) != pkflags {
			t.Errorf("Incorrect bitmask")
		}
		f := bytes.NewReader(s.Data)
		guids := GetSupportedSignatures(f)
		if guids[0] != CERT_SHA1_GUID {
			t.Errorf("Unexpected certificate, should be SHA1")
		}
		if guids[1] != CERT_SHA256_GUID {
			t.Errorf("Unexpected certificate, should be SHA256")
		}
		if guids[2] != CERT_RSA2048_GUID {
			t.Errorf("Unexpected certificate, should be RSA2048")
		}
		if guids[3] != CERT_X509_GUID {
			t.Errorf("Unexpected certificate, should be X509")
		}
	}
}
