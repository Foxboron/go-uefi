package pkcs7

import (
	"crypto"
	"log"
	"os"
	"testing"

	"github.com/foxboron/go-uefi/asntest"
	"golang.org/x/crypto/cryptobyte"
)

func TestVerifySignature(t *testing.T) {
	cert, key = InitCert()
	b, err := SignPKCS7(key, cert, OIDData, []byte{0x00, 0x01})
	if err != nil {
		t.Fatalf("message")
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
	cert, key := asntest.InitCert()

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
