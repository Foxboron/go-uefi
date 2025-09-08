package pkcs7

import (
	"crypto"
	"testing"

	"github.com/foxboron/go-uefi/internal/certtest"
)

func TestSignPKCS7WithAdditionalCerts(t *testing.T) {
	// Create test certificate chain
	key, cert, additionalCerts := certtest.MkCertChain(t)

	// Test data
	h := crypto.SHA256.New()
	h.Write([]byte("test data"))
	content := h.Sum(nil)

	// Sign with additional certificates
	sig, err := SignPKCS7(key, cert, OIDData, content, WithAdditionalCerts(additionalCerts))
	if err != nil {
		t.Fatalf("Failed to sign with additional certificates: %v", err)
	}

	// Parse the PKCS7 signature
	pkcs, err := ParsePKCS7(sig)
	if err != nil {
		t.Fatalf("Failed to parse PKCS7: %v", err)
	}

	// Verify that all certificates are present
	if len(pkcs.Certs) != 3 {
		t.Fatalf("Expected 3 certificates, got %d", len(pkcs.Certs))
	}

	// Verify the signature
	ok, err := pkcs.Verify(cert)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if !ok {
		t.Fatalf("Signature verification failed")
	}
}

func TestSignPKCS7WithoutAdditionalCerts(t *testing.T) {
	// Create test certificate chain
	key, cert, _ := certtest.MkCertChain(t)

	// Test data
	h := crypto.SHA256.New()
	h.Write([]byte("test data"))
	content := h.Sum(nil)

	// Sign without additional certificates (backward compatibility test)
	sig, err := SignPKCS7(key, cert, OIDData, content)
	if err != nil {
		t.Fatalf("Failed to sign without additional certificates: %v", err)
	}

	// Parse the PKCS7 signature
	pkcs, err := ParsePKCS7(sig)
	if err != nil {
		t.Fatalf("Failed to parse PKCS7: %v", err)
	}

	// Verify that only the signing certificate is present
	if len(pkcs.Certs) != 1 {
		t.Fatalf("Expected 1 certificate, got %d", len(pkcs.Certs))
	}

	// Verify the signature
	ok, err := pkcs.Verify(cert)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if !ok {
		t.Fatalf("Signature verification failed")
	}
}

func TestSignPKCS7WithNoCerts(t *testing.T) {
	// Create test certificate chain
	key, cert, additionalCerts := certtest.MkCertChain(t)

	// Test data
	h := crypto.SHA256.New()
	h.Write([]byte("test data"))
	content := h.Sum(nil)

	// Sign with NoCerts option (should not embed any certificates)
	sig, err := SignPKCS7(key, cert, OIDData, content, NoCerts(), WithAdditionalCerts(additionalCerts))
	if err != nil {
		t.Fatalf("Failed to sign with NoCerts option: %v", err)
	}

	// Parse the PKCS7 signature
	pkcs, err := ParsePKCS7(sig)
	if err != nil {
		t.Fatalf("Failed to parse PKCS7: %v", err)
	}

	// Verify that no certificates are present when NoCerts is used
	if len(pkcs.Certs) != 0 {
		t.Fatalf("Expected 0 certificates with NoCerts option, got %d", len(pkcs.Certs))
	}
}
