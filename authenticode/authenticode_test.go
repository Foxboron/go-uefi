package authenticode

import (
	"bytes"
	"crypto"
	"errors"
	"os"
	"testing"

	"github.com/foxboron/go-uefi/asntest"
	"github.com/foxboron/go-uefi/internal/certtest"
)

func TestVerifyAuthenticode(t *testing.T) {
	cert, key := certtest.MkCert(t)

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
	cert, key := certtest.MkCert(t)

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

func TestCheckForgedSignature(t *testing.T) {
	cert, key := certtest.MkCert(t)

	// The binary we intend to sign
	original := mustParse(t, "testdata/test.pecoff")
	sig, err := original.Sign(key, cert)
	if err != nil {
		t.Fatal(err)
	}

	// We graft the above valid signature on to this binary
	fake := mustParse(t, "../tests/data/binary/HelloWorld.efi")

	forged := bytes.Replace(sig, original.Hash(crypto.SHA256), fake.Hash(crypto.SHA256), 1)
	if bytes.Equal(forged, sig) {
		t.Fatalf("digest not found in signature")
	}
	if err := fake.AppendSignature(forged); err != nil {
		t.Fatalf("failed to append the signature ontop of the forged binary")
	}

	reparsed, err := Parse(bytes.NewReader(fake.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	ok, err := reparsed.Verify(cert)
	if ok {
		t.Fatal("go-uefi accepts a forged sinature")
	}

	// Check for other errors
	if !errors.Is(err, ErrNoValidSignatures) {
		t.Fatal(err)
	}
}
