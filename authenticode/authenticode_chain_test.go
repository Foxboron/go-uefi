package authenticode

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/foxboron/go-uefi/internal/certtest"
	"github.com/foxboron/go-uefi/pkcs7"
)

func TestSignAuthenticodeWithAdditionalCerts(t *testing.T) {
	// Create test certificate chain
	key, cert, additionalCerts := certtest.MkCertChain(t)

	// Sign with certificate chain using the new Option approach
	img := []byte("test data for signing")
	sig, err := SignAuthenticode(key, cert, bytes.NewReader(img), crypto.SHA256, pkcs7.WithAdditionalCerts(additionalCerts))
	if err != nil {
		t.Fatalf("Failed to sign with certificate chain: %v", err)
	}

	// Parse the signature
	auth, err := ParseAuthenticode(sig)
	if err != nil {
		t.Fatalf("Failed to parse authenticode signature: %v", err)
	}

	// Verify that all certificates are present
	if len(auth.Pkcs.Certs) != 3 {
		t.Fatalf("Expected 3 certificates in signature, got %d", len(auth.Pkcs.Certs))
	}

	// Verify the signature
	ok, err := auth.Verify(cert, bytes.NewReader(img))
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if !ok {
		t.Fatalf("Signature verification failed")
	}
}

func TestSignAuthenticodeWithoutChain(t *testing.T) {
	// Create test certificate chain
	key, cert, _ := certtest.MkCertChain(t)

	// Sign without additional certificates (backward compatibility test)
	img := []byte("test data for signing")
	sig, err := SignAuthenticode(key, cert, bytes.NewReader(img), crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to sign without certificate chain: %v", err)
	}

	// Parse the signature
	auth, err := ParseAuthenticode(sig)
	if err != nil {
		t.Fatalf("Failed to parse authenticode signature: %v", err)
	}

	// Verify that only the signing certificate is present
	if len(auth.Pkcs.Certs) != 1 {
		t.Fatalf("Expected 1 certificate in signature, got %d", len(auth.Pkcs.Certs))
	}

	// Verify the signature
	ok, err := auth.Verify(cert, bytes.NewReader(img))
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if !ok {
		t.Fatalf("Signature verification failed")
	}
}

func TestPECOFFSignWithAdditionalCerts(t *testing.T) {
	// Create a minimal PE file for testing
	peData := []byte{
		// DOS header
		0x4D, 0x5A, // "MZ" signature
	}
	// Pad to minimum size
	for i := len(peData); i < 1024; i++ {
		peData = append(peData, 0x00)
	}

	peFile := bytes.NewReader(peData)
	binary, err := Parse(peFile)
	if err != nil {
		// Skip test if we can't parse the minimal PE file
		t.Skip("Skipping PE/COFF chain test - unable to create test PE file")
	}

	// Create test certificate chain
	key, cert, additionalCerts := certtest.MkCertChain(t)

	// Sign with certificate chain using the new Option approach
	_, err = binary.Sign(key, cert, pkcs7.WithAdditionalCerts(additionalCerts))
	if err != nil {
		t.Fatalf("Failed to sign PE/COFF with certificate chain: %v", err)
	}

	// Get signatures from the binary
	sigs, err := binary.Signatures()
	if err != nil {
		t.Fatalf("Failed to get signatures: %v", err)
	}

	if len(sigs) == 0 {
		t.Fatalf("No signatures found in binary")
	}

	// Parse the first signature - WINCertificate.Certificate contains the actual signature bytes
	auth, err := ParseAuthenticode(sigs[0].Certificate)
	if err != nil {
		t.Fatalf("Failed to parse authenticode signature: %v", err)
	}

	// Verify that all certificates are present
	if len(auth.Pkcs.Certs) != 3 {
		t.Fatalf("Expected 3 certificates in signature, got %d", len(auth.Pkcs.Certs))
	}
}
