package main

import (
	"crypto"
	"io"
	"log"
	"os"

	"github.com/foxboron/go-uefi/pkcs7"
)

func main() {
	sigFile, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatalf("Failed to open signature file: %v", err)
	}
	defer sigFile.Close()

	sigBytes, err := io.ReadAll(sigFile)
	if err != nil {
		log.Fatalf("Failed to read signature file: %v", err)
	}

	pkcs, err := pkcs7.ParsePKCS7(sigBytes)
	if err != nil {
		log.Fatalf("Failed to parse PKCS7: %v", err)
	}

	ok, err := pkcs.Verify(pkcs.Certs[0], pkcs7.VerifyTimestamp(nil))
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}

	if !ok {
		log.Fatalf("Signature verification failed")
	}

	log.Printf("Signature verification succeeded")

	// now verify timestamp separately
	attrs := pkcs.SignerInfo[0].UnauthenticatedAttributes
	if attrs == nil {
		log.Fatalf("No unauthenticated attributes found, cannot verify timestamp")
	}

	if len(attrs.TimestampToken) == 0 {
		log.Fatalf("No timestamp token found in unauthenticated attributes")
	}

	h := crypto.SHA256.New()
	h.Write(pkcs.SignerInfo[0].EncryptedDigest) // message imprint inside the timestamp token
	imprintHash := h.Sum(nil)

	err = pkcs7.VerifyTimestampBytes(attrs.TimestampToken, imprintHash, pkcs.Certs[0])
	if err != nil {
		log.Printf("Timestamp signature verification failed: %v", err)
	}

	log.Printf("Timestamp signature verification succeeded")
}
