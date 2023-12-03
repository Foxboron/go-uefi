package pkcs7

import (
	"crypto"
	"testing"
)

func TestVerifyAuthenticode(t *testing.T) {
	img := []byte("test")
	h := crypto.SHA256.New()
	h.Write(img)
	b, err := SignAuthenticode(key, cert, h.Sum(nil), crypto.SHA256)
	if err != nil {
		t.Fatalf("message")
	}

	auth, err := ParseAuthenticode(b)
	if err != nil {
		t.Fatalf("%v", err)
	}
	ok, err := auth.Verify(cert, img)
	if err != nil {
		t.Fatalf("failed to verify authenticode checksum: %v", err)
	}

	if !ok {
		t.Fatalf("authenticode signature didn't validate, it should")
	}
}
