package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	encasn1 "encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/foxboron/go-uefi/internal/certtest"
)

func TestCreateTimestampRequest(t *testing.T) {
	messageImprint := []byte("test message")
	hashAlg := pkix.AlgorithmIdentifier{
		Algorithm:  OIDDigestAlgorithmSHA256,
		Parameters: encasn1.RawValue{Tag: 5}, // ASN.1 NULL
	}

	req, err := CreateTimestampRequest(messageImprint, hashAlg)
	if err != nil {
		t.Fatalf("Failed to create timestamp request: %v", err)
	}

	if req.Version != 1 {
		t.Errorf("Expected version 1, got %d", req.Version)
	}

	if !req.MessageImprint.HashAlgorithm.Algorithm.Equal(OIDDigestAlgorithmSHA256) {
		t.Errorf("Hash algorithm mismatch")
	}

	if string(req.MessageImprint.HashedMessage) != string(messageImprint) {
		t.Errorf("Message imprint mismatch")
	}

	if req.Nonce == nil {
		t.Errorf("Expected nonce to be set")
	}

	if !req.CertReq {
		t.Errorf("Expected certificate request to be true")
	}
}

func TestParseTimestampInfo(t *testing.T) {
	// Tests ParseTimestampInfo() function with various inputs (invalid and valid).
	// The timestamp token creation in the happy path is setup, not the test itself -
	// the actual test is whether ParseTimestampInfo() correctly parses the TSTInfo.

	// Test with invalid timestamp token
	invalidToken := []byte("invalid token")
	_, err := ParseTimestampInfo(invalidToken)
	if err == nil {
		t.Errorf("Expected error for invalid timestamp token")
	}

	// Test with empty token
	_, err = ParseTimestampInfo([]byte{})
	if err == nil {
		t.Errorf("Expected error for empty timestamp token")
	}

	// Test with valid PKCS7 but invalid TSTInfo content
	cert, key := certtest.MkCert(t)
	invalidContent := []byte("not a valid TSTInfo structure")
	validPKCS7WithInvalidContent, err := SignPKCS7(key, cert, OIDAttributeTSTInfo, invalidContent)
	if err != nil {
		t.Fatalf("Failed to create test PKCS7: %v", err)
	}

	parsedPKCS7, err := ParsePKCS7(validPKCS7WithInvalidContent)
	if err != nil {
		t.Fatalf("Failed to parse test PKCS7: %v", err)
	}

	_, err = ParseTimestampInfo(parsedPKCS7.ContentInfo)
	if err == nil {
		t.Errorf("Expected error for invalid TSTInfo content")
	}

	messageImprint := []byte("test message imprint")
	hashAlg := pkix.AlgorithmIdentifier{
		Algorithm:  OIDDigestAlgorithmSHA256,
		Parameters: encasn1.RawValue{Tag: 5}, // ASN.1 NULL
	}

	tstInfo := TSTInfo{
		Version: 1,
		Policy:  encasn1.ObjectIdentifier{1, 2, 3, 4},
		MessageImprint: MessageImprint{
			HashAlgorithm: hashAlg,
			HashedMessage: messageImprint,
		},
		SerialNumber: big.NewInt(12345),
		GenTime:      time.Now().UTC(),
	}

	tstInfoBytes, err := tstInfo.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal TSTInfo: %v", err)
	}

	signedToken, err := SignPKCS7(key, cert, OIDAttributeTSTInfo, tstInfoBytes)
	if err != nil {
		t.Fatalf("Failed to create valid PKCS7: %v", err)
	}

	parsedToken, err := ParsePKCS7(signedToken)
	if err != nil {
		t.Fatalf("Failed to parse valid PKCS7: %v", err)
	}

	parsedInfo, err := ParseTimestampInfo(parsedToken.ContentInfo)
	if err != nil {
		t.Fatalf("Expected no error for valid timestamp token, got: %v", err)
	}

	if parsedInfo.Version != 1 {
		t.Fatalf("Expected version 1, got %d", parsedInfo.Version)
	}

	if !bytes.Equal(parsedInfo.MessageImprint.HashedMessage, messageImprint) {
		t.Fatalf("Message imprint mismatch")
	}
}

func TestGetTimestampValidation(t *testing.T) {
	// Test with empty URL
	_, err := GetTimestamp("", []byte("test"))
	if err == nil {
		t.Errorf("Expected error for empty TSA URL")
	}

	// Test with invalid URL
	_, err = GetTimestamp("invalid-url", []byte("test"))
	if err == nil {
		t.Errorf("Expected error for invalid TSA URL")
	}

	// Test with malformed URL that would fail parsing
	_, err = GetTimestamp("://malformed", []byte("test"))
	if err == nil {
		t.Errorf("Expected error for malformed TSA URL")
	}
}

func TestRealTimestampRequest(t *testing.T) {
	// Skip this test in short mode or CI environments
	if testing.Short() {
		t.Skip("Skipping real timestamp request test in short mode")
	}

	// Create a test message imprint (hash of some data)
	testData := []byte("This is test data for timestamp verification")
	h := crypto.SHA256.New()
	h.Write(testData)
	messageImprint := h.Sum(nil)

	// Request a timestamp from DigiCert's TSA
	tsaURL := "http://timestamp.digicert.com"
	timestampToken, err := GetTimestamp(tsaURL, messageImprint)
	if err != nil {
		t.Fatalf("Failed to get timestamp from %s: %v", tsaURL, err)
	}

	if len(timestampToken) == 0 {
		t.Errorf("Expected non-empty timestamp token")
	}

	token, err := ParsePKCS7(timestampToken)
	if err != nil {
		t.Fatalf("Failed to parse timestamp token as pkcs7: %v", err)
	}

	// Parse the timestamp token to validate its structure
	tstInfo, err := ParseTimestampInfo(token.ContentInfo)
	if err != nil {
		t.Fatalf("Failed to parse timestamp token: %v", err)
	}

	// Verify the message imprint matches
	if !bytes.Equal(tstInfo.MessageImprint.HashedMessage, messageImprint) {
		t.Errorf("Timestamp message imprint does not match original")
	}

	// Verify the timestamp is recent (within the last hour)
	now := time.Now()
	if tstInfo.GenTime.After(now) || tstInfo.GenTime.Before(now.Add(-time.Hour)) {
		t.Errorf("Timestamp time %v is not within expected range (last hour from %v)", tstInfo.GenTime, now)
	}
}

func TestSignPKCS7WithTimestamp(t *testing.T) {
	// Skip this test in short mode or CI environments
	if testing.Short() {
		t.Skip("Skipping PKCS7 with timestamp test in short mode")
	}

	cert, key := certtest.MkCert(t)
	content := []byte("test content for timestamped signature")

	// Sign with timestamp
	tsaURL := "http://timestamp.digicert.com"
	sig, err := SignPKCS7(key, cert, OIDData, content, WithAuthenticodeTimestamp(tsaURL))
	if err != nil {
		t.Fatalf("Failed to sign with timestamp: %v", err)
	}

	// Parse the PKCS7 signature
	pkcs, err := ParsePKCS7(sig)
	if err != nil {
		t.Fatalf("Failed to parse timestamped PKCS7: %v", err)
	}

	// Verify the signature
	ok, err := pkcs.Verify(cert)
	if err != nil {
		t.Fatalf("Failed to verify timestamped signature: %v", err)
	}
	if !ok {
		t.Fatalf("Timestamped signature verification failed")
	}

	// Check that the timestamp token is present in unauthenticated attributes
	if len(pkcs.SignerInfo) == 0 {
		t.Fatalf("No signer info found")
	}

	attrs := pkcs.SignerInfo[0].UnauthenticatedAttributes
	if attrs == nil {
		t.Fatalf("No unauthenticated attributes found")
	}

	if len(attrs.TimestampToken) == 0 {
		t.Fatalf("No timestamp token found in unauthenticated attributes")
	}

	token, err := ParsePKCS7(attrs.TimestampToken)
	if err != nil {
		t.Fatalf("Failed to parse timestamp token as pkcs7: %v", err)
	}

	// Parse the embedded timestamp token
	tstInfo, err := ParseTimestampInfo(token.ContentInfo)
	if err != nil {
		t.Fatalf("Failed to parse embedded timestamp token: %v", err)
	}

	// Verify the timestamp is recent
	now := time.Now()
	if tstInfo.GenTime.After(now) || tstInfo.GenTime.Before(now.Add(-time.Hour)) {
		t.Errorf("Embedded timestamp time %v is not within expected range", tstInfo.GenTime)
	}

	h := crypto.SHA256.New()
	h.Write(pkcs.SignerInfo[0].EncryptedDigest) // message imprint inside the timestamp token
	err = VerifyTimestampBytes(attrs.TimestampToken, h.Sum(nil), pkcs.Certs[0])
	if err != nil {
		t.Fatalf("Failed to verify embedded timestamp token: %v", err)
	}
}

func TestVerifyTimestampValidation(t *testing.T) {
	cert, key := certtest.MkCert(t)

	// Create invalid timestamp token
	invalidToken := []byte("invalid token")
	messageImprint := []byte("test message")

	err := VerifyTimestampBytes(invalidToken, messageImprint, cert)
	if err == nil {
		t.Errorf("Expected error for invalid timestamp token")
	}

	// Test with empty trusted certificates
	validToken, err := SignPKCS7(key, cert, OIDData, []byte("test"))
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	err = VerifyTimestampBytes(validToken, messageImprint, nil)
	if err == nil {
		t.Errorf("Expected error for empty trusted certificates")
	}

	// Happy path: Create valid timestamp token and verify it successfully
	testData := []byte("data to be timestamped")
	h := crypto.SHA256.New()
	h.Write(testData)
	validMessageImprint := h.Sum(nil)

	hashAlg := pkix.AlgorithmIdentifier{
		Algorithm:  OIDDigestAlgorithmSHA256,
		Parameters: encasn1.RawValue{Tag: 5},
	}

	tstInfo := TSTInfo{
		Version: 1,
		Policy:  encasn1.ObjectIdentifier{1, 2, 3, 4},
		MessageImprint: MessageImprint{
			HashAlgorithm: hashAlg,
			HashedMessage: validMessageImprint,
		},
		SerialNumber: big.NewInt(99999),
		GenTime:      time.Now().UTC(),
	}

	tstInfoBytes, err := tstInfo.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal TSTInfo: %v", err)
	}

	validTimestampToken, err := SignPKCS7(key, cert, OIDAttributeTSTInfo, tstInfoBytes)
	if err != nil {
		t.Fatalf("Failed to create valid timestamp token: %v", err)
	}

	// Verify the timestamp token with correct message imprint and trusted cert
	err = VerifyTimestampBytes(validTimestampToken, validMessageImprint, cert)
	if err != nil {
		t.Errorf("Expected no error for valid timestamp verification, got: %v", err)
	}

	// Verify that verification fails with wrong message imprint
	wrongImprint := []byte("wrong message imprint")
	err = VerifyTimestampBytes(validTimestampToken, wrongImprint, cert)
	if err == nil {
		t.Errorf("Expected error when verifying with wrong message imprint")
	}
}
