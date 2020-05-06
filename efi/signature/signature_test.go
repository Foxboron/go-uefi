package secureboot

import (
	"bytes"
	"io/ioutil"
	"log"
	"path/filepath"
	"testing"

	"github.com/foxboron/goefi/efi/attributes"
)

func TestParseSignatureList(t *testing.T) {
	dir := "../../tests/data/keys/pk"
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
		ReadSignatureList(f)
		break
	}
}

func TestParseSignatureSupport(t *testing.T) {
	file := "../../tests/data/signature/SignatureSupport-8be4df61-93ca-11d2-aa0d-00e098032b8c"
	s, _ := attributes.ReadEfivarsFile(file)

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
