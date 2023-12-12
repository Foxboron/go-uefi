package pkcs7

import (
	"os"
	"testing"
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
