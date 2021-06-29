package signature

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/foxboron/go-uefi/efi/attributes"
	"github.com/foxboron/go-uefi/efi/util"
	"go.mozilla.org/pkcs7"
)

func ReadTestData(dir string) []string {
	var paths []string
	files, _ := ioutil.ReadDir(dir)
	for _, file := range files {
		paths = append(paths, filepath.Join(dir, file.Name()))
	}
	return paths
}

var (
	EfivarsTestFiles         = ReadTestData("../../tests/data/signatures/efivars")
	SiglistTestFiles         = ReadTestData("../../tests/data/signatures/siglist")
	SiglistchecksumTestFiles = ReadTestData("../../tests/data/signatures/siglistchecksum")
	SigsupportTestFiles      = ReadTestData("../../tests/data/signatures/sigsupport")
)

func TestParseSignatureListVars(t *testing.T) {
	for _, path := range EfivarsTestFiles {
		attrs, data, _ := attributes.ReadEfivarsFile(path)
		var pkflags attributes.Attributes
		pkflags |= attributes.EFI_VARIABLE_NON_VOLATILE
		pkflags |= attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS
		pkflags |= attributes.EFI_VARIABLE_RUNTIME_ACCESS
		pkflags |= attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
		if (pkflags & attrs) != pkflags {
			t.Errorf("Incorrect bitmask")
		}

		c, err := ReadSignatureList(data)
		if err != nil {
			t.Fatal(err)
		}
		if util.CmpEFIGUID(c.SignatureType, CERT_X509_GUID) {
			// Run over and ensure we are getting the correct type
			for _, d := range c.Signatures {
				_, err := pkcs7.NewSignedData(d.Data)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestParseSignatureListFile(t *testing.T) {
	for _, path := range SiglistTestFiles {
		b, _ := ioutil.ReadFile(path)
		f := bytes.NewReader(b)
		c, err := ReadSignatureList(f)
		if err != nil {
			t.Fatal(err)
		}
		if util.CmpEFIGUID(c.SignatureType, CERT_X509_GUID) {
			for _, d := range c.Signatures {
				_, err := pkcs7.NewSignedData(d.Data)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestParseSignatureListHashFile(t *testing.T) {
	for _, path := range SiglistchecksumTestFiles {
		b, _ := ioutil.ReadFile(path)
		f := bytes.NewReader(b)
		c, err := ReadSignatureList(f)
		if err != nil {
			t.Fatal(err)
		}
		if util.CmpEFIGUID(c.SignatureType, CERT_SHA256_GUID) {
			for _, d := range c.Signatures {
				if fmt.Sprintf("%x", d.Data) != "4be2e8d5ef8113c3b9218f05f8aed1df8a6b0e24c706360d39f74a7423f00e32" {
					t.Fatal("Not correct checksum")
				}
			}
		}
	}
}

func TestParseSignatureSupport(t *testing.T) {
	for _, path := range SigsupportTestFiles {
		attrs, data, _ := attributes.ReadEfivarsFile(path)
		var pkflags attributes.Attributes
		pkflags |= attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS
		pkflags |= attributes.EFI_VARIABLE_RUNTIME_ACCESS
		if (pkflags & attrs) != pkflags {
			t.Errorf("Incorrect bitmask")
		}
		guids, err := GetSupportedSignatures(data)
		if err != nil {
			t.Fatal(err)
		}
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

var sigdata = []SignatureData{
	SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x81, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
	SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x82, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
	SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x83, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
}

func TestSiglist(t *testing.T) {
	sl := NewSignatureList(CERT_SHA256_GUID)
	for _, sig := range sigdata {
		sl.AppendBytes(sig.Owner, sig.Data)
	}
	if sl.ListSize != 172 {
		t.Fatal("list size incorrect")
	}
	if sl.Size != 48 {
		t.Fatal("size incorrect")
	}
	if len(sl.Signatures) != 3 {
		t.Fatal("number of signatures wrong")
	}
}

func TestSiglistExists(t *testing.T) {
	sl1 := NewSignatureList(CERT_SHA256_GUID)
	for _, sig := range sigdata {
		sl1.AppendBytes(sig.Owner, sig.Data)
	}
	sl2 := NewSignatureList(CERT_SHA256_GUID)
	for _, sig := range sigdata {
		sl2.AppendBytes(sig.Owner, sig.Data)
	}
	if !sl1.ExistsInList(sl2) {
		t.Fatal("exists: not the same list")
	}
}

func TestSiglistSigDataExists(t *testing.T) {
	sl := NewSignatureList(CERT_SHA256_GUID)
	for _, sig := range sigdata {
		sl.AppendBytes(sig.Owner, sig.Data)
	}
	if ok, _ := sl.Exists(&sigdata[0]); !ok {
		t.Fatal("exists: sigdata is not in the list")
	}
}
