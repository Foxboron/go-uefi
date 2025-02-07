package authenticode

import (
	"bytes"
	"crypto"
	"os"
	"testing"

	"github.com/foxboron/go-uefi/asntest"
)

func TestVerifyAuthenticode(t *testing.T) {
	cert, key := asntest.InitCert()

	img := []byte("test")
	b, err := SignAuthenticode(key, cert, bytes.NewReader(img), crypto.SHA256)
	if err != nil {
		t.Fatalf("message")
	}

	auth, err := ParseAuthenticode(b)
	if err != nil {
		t.Fatalf("%v", err)
	}
	ok, err := auth.Verify(cert, bytes.NewReader(img))
	if err != nil {
		t.Fatalf("failed to verify authenticode checksum: %v", err)
	}

	if !ok {
		t.Fatalf("authenticode signature didn't validate, it should")
	}
}

func TestParseSbsign(t *testing.T) {
	b, err := os.ReadFile("testdata/test.authenticode.signed")
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseAuthenticode(b)
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

	b, err := os.ReadFile("testdata/old_authenticode_implementation.der")
	if err != nil {
		t.Fatal(err)
	}

	img := []byte{0x00, 0x01}
	bb, err := SignAuthenticode(key, cert, bytes.NewReader(img), crypto.SHA256)
	if err != nil {
		t.Fatalf("failed signing digest")
	}

	// We should see a couple of differences, but largely the same structure should be present
	asntest.Asn1Compare(t, b, bb)
}
