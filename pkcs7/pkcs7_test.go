package pkcs7

import "testing"

func TestVerifySignature(t *testing.T) {
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
