package pkcs7

import (
	"crypto"
	encasn1 "encoding/asn1"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/foxboron/go-uefi/asntest"
	"github.com/foxboron/go-uefi/internal/certtest"
	"golang.org/x/crypto/cryptobyte"
)

func TestVerifySignature(t *testing.T) {
	cert, key := certtest.MkCert(t)
	// TODO: Introduce negative cases
	for n, c := range []struct {
		t       string
		options []Option
		data    []byte
		oid     encasn1.ObjectIdentifier
	}{
		{
			t:       "Base case",
			options: []Option{},
			data:    []byte{0x00, 0x01},
			oid:     OIDData,
		},
		{
			t:       "All options",
			options: []Option{NoAttr(), NoCerts()},
			data:    []byte{0x00, 0x01},
			oid:     OIDData,
		},
	} {
		t.Run(fmt.Sprintf("%d - %s", n, c.t), func(t *testing.T) {
			b, err := SignPKCS7(key, cert, c.oid, c.data)
			if err != nil {
				t.Fatalf("failed signing: %v", err)
			}
			pkcs, err := ParsePKCS7(b)
			if err != nil {
				t.Fatalf("failed parsing PKCS7 signature: %v", err)
			}

			ok, err := pkcs.Verify(cert)
			if err != nil {
				t.Fatalf("failed verifying signature: %v", err)
			}

			if !ok {
				t.Fatalf("Signature should validate")
			}
		})
	}
}

// Try to parse a signature created by sbvarsign
func TestParseSbvarignSignature(t *testing.T) {
	b, err := os.ReadFile("testdata/test.signed")
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParsePKCS7(b)
	if err != nil {
		t.Fatalf("failed to parse pkcs7: %v", err)
	}
}

// This test compares the library ASN.1 output to the old implementation
// This is mostly for debugging the implementation.
func TestCompareOldImplementation(t *testing.T) {
	if !testing.Verbose() {
		return
	}
	cert, key := certtest.MkCert(t)

	b, err := os.ReadFile("testdata/old_pkcs7_implementation.der")
	if err != nil {
		t.Fatal(err)
	}

	img := []byte{0x00, 0x01}
	h := crypto.SHA256.New()
	h.Write(img)
	bb, err := SignPKCS7(key, cert, OIDData, h.Sum(nil))
	if err != nil {
		t.Fatalf("failed signing digest")
	}

	cs := cryptobyte.String(bb)
	_, bytes, err := ParseContentInfo(&cs)
	if err != nil {
		log.Fatal(err)
	}

	// We should see a couple of differences, but largely the same structure should be present
	asntest.Asn1Compare(t, b, bytes)
}
