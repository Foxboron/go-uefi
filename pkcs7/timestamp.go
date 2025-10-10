package pkcs7

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	encasn1 "encoding/asn1"
)

// TSAPolicyId represents a timestamp policy identifier
type TSAPolicyId encasn1.ObjectIdentifier

// TSAQualifier represents a timestamp qualifier
type TSAQualifier struct {
	Qualifier string
}

// MessageImprint contains the hash of the data to be time-stamped
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// TSAReq represents a Time Stamp Request as defined in RFC 3161
type TSAReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      TSAPolicyId      `asn1:"optional"`
	Nonce          *big.Int         `asn1:"optional"`
	CertReq        bool             `asn1:"optional"`
	Extensions     []pkix.Extension `asn1:"tag:0,optional"`
}

// CreateTimestampRequest creates a RFC 3161 timestamp request
func CreateTimestampRequest(messageImprint []byte, hashAlg pkix.AlgorithmIdentifier) (*TSAReq, error) {
	// Generate a random nonce
	nonce, err := rand.Int(rand.Reader, big.NewInt(1<<63-1))
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	req := &TSAReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: hashAlg,
			HashedMessage: messageImprint,
		},
		Nonce:   nonce,
		CertReq: true,
	}

	return req, nil
}

// Marshal encodes the TSAReq using cryptobytes
func (r *TSAReq) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// version INTEGER
		b.AddASN1Int64(int64(r.Version))

		// messageImprint MessageImprint
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			// hashAlgorithm AlgorithmIdentifier
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(r.MessageImprint.HashAlgorithm.Algorithm)
				if len(r.MessageImprint.HashAlgorithm.Parameters.FullBytes) > 0 {
					b.AddBytes(r.MessageImprint.HashAlgorithm.Parameters.FullBytes)
				} else {
					b.AddASN1NULL()
				}
			})
			// hashedMessage OCTET STRING
			b.AddASN1OctetString(r.MessageImprint.HashedMessage)
		})

		// reqPolicy TSAPolicyId OPTIONAL
		if len(r.ReqPolicy) > 0 {
			b.AddASN1ObjectIdentifier(encasn1.ObjectIdentifier(r.ReqPolicy))
		}

		// nonce INTEGER OPTIONAL
		if r.Nonce != nil {
			b.AddASN1BigInt(r.Nonce)
		}

		// certReq BOOLEAN DEFAULT FALSE
		if r.CertReq {
			b.AddASN1Boolean(r.CertReq)
		}

		// extensions [0] IMPLICIT Extensions OPTIONAL
		if len(r.Extensions) > 0 {
			b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				for _, ext := range r.Extensions {
					b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(ext.Id)
						if ext.Critical {
							b.AddASN1Boolean(ext.Critical)
						}
						b.AddASN1OctetString(ext.Value)
					})
				}
			})
		}
	})

	return b.Bytes()
}

// PKIStatus represents the status of a PKI response
type PKIStatus int

const (
	PKIStatusGranted                PKIStatus = 0
	PKIStatusGrantedWithMods        PKIStatus = 1
	PKIStatusRejection              PKIStatus = 2
	PKIStatusWaiting                PKIStatus = 3
	PKIStatusRevocationWarning      PKIStatus = 4
	PKIStatusRevocationNotification PKIStatus = 5
)

// PKIFreeText represents free text in a PKI response
type PKIFreeText []string

// PKIFailureInfo represents failure information
type PKIFailureInfo encasn1.BitString

// PKIStatus contains the status information of a timestamp response
type PKIStatusInfo struct {
	Status       PKIStatus      `asn1:""`
	StatusString PKIFreeText    `asn1:"optional"`
	FailInfo     PKIFailureInfo `asn1:"optional"`
}

// TSAResp represents a Time Stamp Response as defined in RFC 3161
type TSAResp struct {
	Status  PKIStatusInfo
	TSToken []byte // Optional: the timestamp token (PKCS#7 SignedData)
}

// TSTInfo represents the timestamp info structure
type TSTInfo struct {
	Version        int                      `asn1:""`
	Policy         encasn1.ObjectIdentifier `asn1:""`
	MessageImprint MessageImprint           `asn1:""`
	SerialNumber   *big.Int                 `asn1:""`
	GenTime        time.Time                `asn1:"generalized"`
	Accuracy       Accuracy                 `asn1:"optional"`
	Ordering       bool                     `asn1:"optional"`
	Nonce          *big.Int                 `asn1:"optional"`
	TSA            []byte                   `asn1:"tag:0,optional"`
	Extensions     []pkix.Extension         `asn1:"tag:1,optional"`
}

// Accuracy represents timestamp accuracy
type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"tag:0,optional"`
	Micros  int `asn1:"tag:1,optional"`
}

// Marshal encodes the TSTInfo using cryptobytes
func (t *TSTInfo) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// version INTEGER
		b.AddASN1Int64(int64(t.Version))

		// policy OBJECT IDENTIFIER
		b.AddASN1ObjectIdentifier(t.Policy)

		// messageImprint MessageImprint
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			// hashAlgorithm AlgorithmIdentifier
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(t.MessageImprint.HashAlgorithm.Algorithm)
				if len(t.MessageImprint.HashAlgorithm.Parameters.FullBytes) > 0 {
					b.AddBytes(t.MessageImprint.HashAlgorithm.Parameters.FullBytes)
				} else {
					b.AddASN1NULL()
				}
			})
			// hashedMessage OCTET STRING
			b.AddASN1OctetString(t.MessageImprint.HashedMessage)
		})

		// serialNumber INTEGER
		b.AddASN1BigInt(t.SerialNumber)

		// genTime GeneralizedTime
		genTimeStr := t.GenTime.UTC().Format("20060102150405Z")
		b.AddASN1(asn1.GeneralizedTime, func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(genTimeStr))
		})

		// accuracy Accuracy OPTIONAL
		if t.Accuracy.Seconds != 0 || t.Accuracy.Millis != 0 || t.Accuracy.Micros != 0 {
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				// seconds INTEGER OPTIONAL
				if t.Accuracy.Seconds != 0 {
					b.AddASN1Int64(int64(t.Accuracy.Seconds))
				}
				// millis [0] IMPLICIT INTEGER OPTIONAL
				// For IMPLICIT tags, we write the integer bytes directly with the context-specific tag
				if t.Accuracy.Millis != 0 {
					millisBytes := big.NewInt(int64(t.Accuracy.Millis)).Bytes()
					b.AddASN1(asn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes(millisBytes)
					})
				}
				// micros [1] IMPLICIT INTEGER OPTIONAL
				if t.Accuracy.Micros != 0 {
					microsBytes := big.NewInt(int64(t.Accuracy.Micros)).Bytes()
					b.AddASN1(asn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes(microsBytes)
					})
				}
			})
		}

		// ordering BOOLEAN DEFAULT FALSE
		if t.Ordering {
			b.AddASN1Boolean(t.Ordering)
		}

		// nonce INTEGER OPTIONAL
		if t.Nonce != nil {
			b.AddASN1BigInt(t.Nonce)
		}

		// tsa [0] GeneralName OPTIONAL
		if len(t.TSA) > 0 {
			b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddBytes(t.TSA)
			})
		}

		// extensions [1] Extensions OPTIONAL
		if len(t.Extensions) > 0 {
			b.AddASN1(asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				for _, ext := range t.Extensions {
					b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(ext.Id)
						if ext.Critical {
							b.AddASN1Boolean(ext.Critical)
						}
						b.AddASN1OctetString(ext.Value)
					})
				}
			})
		}
	})

	return b.Bytes()
}

// RequestTimestamp requests a timestamp from a TSA server
func RequestTimestamp(tsaURL string, req *TSAReq) (*TSAResp, error) {
	// Marshal the timestamp request
	reqBytes, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal timestamp request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequest("POST", tsaURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	httpReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(reqBytes)))

	// Send request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send timestamp request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("timestamp server returned status %d", httpResp.StatusCode)
	}

	// Read response
	respBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read timestamp response: %w", err)
	}

	// Parse the TSA response structure using cryptobytes
	resp, err := parseTSAResp(respBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TSA response: %w", err)
	}

	// Check status
	if resp.Status.Status != PKIStatusGranted {
		return nil, fmt.Errorf("timestamp request rejected with status %d", resp.Status.Status)
	}

	return resp, nil
}

// parseTSAResp parses a TSA response using cryptobytes
func parseTSAResp(data []byte) (*TSAResp, error) {
	s := cryptobyte.String(data)
	var respSeq cryptobyte.String
	if !s.ReadASN1(&respSeq, asn1.SEQUENCE) {
		return nil, errors.New("failed to read TSAResp SEQUENCE")
	}

	// Parse PKIStatusInfo
	var statusSeq cryptobyte.String
	if !respSeq.ReadASN1(&statusSeq, asn1.SEQUENCE) {
		return nil, errors.New("failed to read PKIStatusInfo SEQUENCE")
	}

	var status int64
	if !statusSeq.ReadASN1Integer(&status) {
		return nil, errors.New("failed to read status INTEGER")
	}

	resp := &TSAResp{
		Status: PKIStatusInfo{
			Status: PKIStatus(status),
		},
	}

	// Optional: statusString (PKIFreeText) - SEQUENCE OF UTF8String
	if statusSeq.PeekASN1Tag(asn1.SEQUENCE) {
		var freeTextSeq cryptobyte.String
		if !statusSeq.ReadASN1(&freeTextSeq, asn1.SEQUENCE) {
			return nil, errors.New("failed to read PKIFreeText SEQUENCE")
		}
		var freeText []string
		for !freeTextSeq.Empty() {
			var textBytes []byte
			if !freeTextSeq.ReadASN1Bytes(&textBytes, asn1.UTF8String) {
				return nil, errors.New("failed to read UTF8String from PKIFreeText")
			}
			freeText = append(freeText, string(textBytes))
		}
		resp.Status.StatusString = freeText
	}

	// Optional: failInfo (PKIFailureInfo) - BIT STRING
	if statusSeq.PeekASN1Tag(asn1.BIT_STRING) {
		var failInfo encasn1.BitString
		if !statusSeq.ReadASN1BitString(&failInfo) {
			return nil, errors.New("failed to read failInfo BIT STRING")
		}
		resp.Status.FailInfo = PKIFailureInfo(failInfo)
	}

	// Optional: TSToken (timestamp token) - this is a SEQUENCE (ContentInfo)
	if !respSeq.Empty() {
		resp.TSToken = []byte(respSeq)
	}

	return resp, nil
}

// GetTimestamp requests a timestamp for the given message imprint
func GetTimestamp(tsaURL string, messageImprint []byte) ([]byte, error) {
	if tsaURL == "" {
		return nil, errors.New("TSA URL is required")
	}

	// Parse URL to validate
	_, err := url.Parse(tsaURL)
	if err != nil {
		return nil, fmt.Errorf("invalid TSA URL: %w", err)
	}

	// Create hash algorithm identifier for SHA256
	hashAlg := pkix.AlgorithmIdentifier{
		Algorithm:  OIDDigestAlgorithmSHA256,
		Parameters: encasn1.RawValue{Tag: 5}, // ASN.1 NULL
	}

	// Create timestamp request
	req, err := CreateTimestampRequest(messageImprint, hashAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to create timestamp request: %w", err)
	}

	// Request timestamp from server
	resp, err := RequestTimestamp(tsaURL, req)
	if err != nil {
		return nil, fmt.Errorf("failed to request timestamp: %w", err)
	}

	return resp.TSToken, nil
}

// VerifyTimestampBytes verifies a RFC 3161 timestamp token and validates it against the provided message imprint.
// It performs the following verifications:
//   - Parses the timestampToken as a PKCS#7 signed data structure
//   - Extracts and validates the TSTInfo (timestamp information)
//   - Verifies the timestamp generation time is within the signing certificate's validity period
//   - Confirms the message imprint in the timestamp matches the provided messageImprint
//   - Validates the TSA certificate chain against trusted roots
//   - Verifies the timestamp signature using the TSA certificate
func VerifyTimestampBytes(timestampToken []byte, messageImprint []byte, signerCert *x509.Certificate, opts ...VerifyOption) error {
	// Parse the timestamp token (which is a PKCS7 signed data structure)
	token, err := ParsePKCS7(timestampToken)
	if err != nil {
		return fmt.Errorf("failed to parse timestamp token: %w", err)
	}

	// Extract TSTInfo using the proper parsing function that handles OCTET STRING wrapping
	tstInfo, err := ParseTimestampInfo(token.ContentInfo)
	if err != nil {
		return fmt.Errorf("failed to parse TSTInfo: %w", err)
	}

	// Ensure generation time is present
	if tstInfo.GenTime.IsZero() {
		return errors.New("timestamp token has no generation time")
	}

	// Verify generation time within certificate validity period
	if tstInfo.GenTime.Before(signerCert.NotBefore) || tstInfo.GenTime.After(signerCert.NotAfter) {
		return errors.New("timestamp generation time is outside the validity period of the signing certificate")
	}

	// Verify the message imprint matches
	if !bytes.Equal(tstInfo.MessageImprint.HashedMessage, messageImprint) {
		return fmt.Errorf("timestamp message imprint does not match %x vs %x", tstInfo.MessageImprint.HashedMessage, messageImprint)
	}

	if len(token.Certs) == 0 {
		return errors.New("no certificates in timestamp token")
	}

	tsaCert := token.Certs[0]

	c := &VerifyConfig{}
	for _, optFunc := range opts {
		optFunc(c)
	}

	if len(c.TSARoots) > 0 {
		intermediatePool := x509.NewCertPool()
		for _, c := range token.Certs[1:] {
			intermediatePool.AddCert(c)
		}
		x509opts := x509.VerifyOptions{
			Roots:         x509.NewCertPool(),
			Intermediates: intermediatePool,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		}
		for _, root := range c.TSARoots {
			x509opts.Roots.AddCert(root)
		}
		if _, err := tsaCert.Verify(x509opts); err != nil {
			return fmt.Errorf("failed to verify TSA certificate: %w", err)
		}
	}

	// Verify the timestamp signature against the TSA certificate
	ok, err := token.Verify(tsaCert)
	if err != nil {
		return fmt.Errorf("failed to verify timestamp signature: %w", err)
	}
	if !ok {
		return fmt.Errorf("timestamp signature verification failed")
	}

	return nil
}

// ParseTimestampInfo parses and extracts TSTInfo (timestamp token information) from PKCS#7 contentInfo.
//
// contentInfo may be the raw ASN.1 encoded content from a PKCS#7 timestamp token, which may be
// either a TSTInfo structure directly or wrapped in an OCTET STRING
func ParseTimestampInfo(contentInfo []byte) (*TSTInfo, error) {
	// Try parsing contentInfo as TSTInfo first
	tstInfo, err := parseTSTInfo(contentInfo)
	if err == nil {
		return tstInfo, nil
	}

	// The content is wrapped in an OCTET STRING, extract it
	s := cryptobyte.String(contentInfo)
	var octetString []byte
	if !s.ReadASN1Bytes(&octetString, asn1.OCTET_STRING) {
		return nil, errors.New("failed to parse OCTET STRING wrapper")
	}

	// Parse the octet string content as TSTInfo
	tstInfo, err = parseTSTInfo(octetString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TSTInfo from OCTET STRING: %w", err)
	}

	return tstInfo, nil
}

// parseTSTInfo parses TSTInfo structure using cryptobytes
func parseTSTInfo(data []byte) (*TSTInfo, error) {
	s := cryptobyte.String(data)
	var tstSeq cryptobyte.String
	if !s.ReadASN1(&tstSeq, asn1.SEQUENCE) {
		return nil, errors.New("failed to read TSTInfo SEQUENCE")
	}

	var tstInfo TSTInfo

	// version INTEGER
	var version int64
	if !tstSeq.ReadASN1Integer(&version) {
		return nil, errors.New("failed to read version")
	}
	tstInfo.Version = int(version)

	// policy OBJECT IDENTIFIER
	if !tstSeq.ReadASN1ObjectIdentifier(&tstInfo.Policy) {
		return nil, errors.New("failed to read policy OID")
	}

	// messageImprint MessageImprint
	var msgImprintSeq cryptobyte.String
	if !tstSeq.ReadASN1(&msgImprintSeq, asn1.SEQUENCE) {
		return nil, errors.New("failed to read MessageImprint SEQUENCE")
	}

	// Parse MessageImprint: hashAlgorithm and hashedMessage
	hashAlg, err := ParseAlgorithmIdentifier(&msgImprintSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hash algorithm: %w", err)
	}
	tstInfo.MessageImprint.HashAlgorithm = *hashAlg

	if !msgImprintSeq.ReadASN1Bytes(&tstInfo.MessageImprint.HashedMessage, asn1.OCTET_STRING) {
		return nil, errors.New("failed to read hashedMessage")
	}

	// serialNumber INTEGER
	tstInfo.SerialNumber = new(big.Int)
	if !tstSeq.ReadASN1Integer(tstInfo.SerialNumber) {
		return nil, errors.New("failed to read serialNumber")
	}

	// genTime GeneralizedTime
	var genTimeBytes []byte
	if !tstSeq.ReadASN1Bytes(&genTimeBytes, asn1.GeneralizedTime) {
		return nil, errors.New("failed to read genTime")
	}
	genTime, err := time.Parse("20060102150405Z", string(genTimeBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse genTime: %w", err)
	}
	tstInfo.GenTime = genTime

	// Optional fields
	// accuracy Accuracy OPTIONAL
	if tstSeq.PeekASN1Tag(asn1.SEQUENCE) {
		var accSeq cryptobyte.String
		if !tstSeq.ReadASN1(&accSeq, asn1.SEQUENCE) {
			return nil, errors.New("failed to read Accuracy SEQUENCE")
		}

		// All fields in Accuracy are optional
		// seconds INTEGER OPTIONAL
		if accSeq.PeekASN1Tag(asn1.INTEGER) {
			var seconds int64
			if !accSeq.ReadASN1Integer(&seconds) {
				return nil, errors.New("failed to read accuracy seconds")
			}
			tstInfo.Accuracy.Seconds = int(seconds)
		}

		// millis [0] IMPLICIT INTEGER (1..999) OPTIONAL
		// With IMPLICIT tagging, the tag replaces INTEGER tag, so we read bytes directly
		if accSeq.PeekASN1Tag(asn1.Tag(0).ContextSpecific()) {
			var millisBytes []byte
			if !accSeq.ReadASN1Bytes(&millisBytes, asn1.Tag(0).ContextSpecific()) {
				return nil, errors.New("failed to read accuracy millis")
			}
			tstInfo.Accuracy.Millis = int(new(big.Int).SetBytes(millisBytes).Int64())
		}

		// micros [1] IMPLICIT INTEGER (1..999) OPTIONAL
		// With IMPLICIT tagging, the tag replaces INTEGER tag, so we read bytes directly
		if accSeq.PeekASN1Tag(asn1.Tag(1).ContextSpecific()) {
			var microsBytes []byte
			if !accSeq.ReadASN1Bytes(&microsBytes, asn1.Tag(1).ContextSpecific()) {
				return nil, errors.New("failed to read accuracy micros")
			}
			tstInfo.Accuracy.Micros = int(new(big.Int).SetBytes(microsBytes).Int64())
		}
	}

	// ordering BOOLEAN DEFAULT FALSE
	if tstSeq.PeekASN1Tag(asn1.BOOLEAN) {
		if !tstSeq.ReadASN1Boolean(&tstInfo.Ordering) {
			return nil, errors.New("failed to read ordering")
		}
	}

	// nonce INTEGER OPTIONAL
	if tstSeq.PeekASN1Tag(asn1.INTEGER) {
		tstInfo.Nonce = new(big.Int)
		if !tstSeq.ReadASN1Integer(tstInfo.Nonce) {
			return nil, errors.New("failed to read nonce")
		}
	}

	// tsa [0] GeneralName OPTIONAL
	if tstSeq.PeekASN1Tag(asn1.Tag(0).ContextSpecific().Constructed()) {
		var tsaBytes cryptobyte.String
		if !tstSeq.ReadASN1(&tsaBytes, asn1.Tag(0).ContextSpecific().Constructed()) {
			return nil, errors.New("failed to read tsa")
		}
		tstInfo.TSA = []byte(tsaBytes)
	}

	// extensions [1] Extensions OPTIONAL
	if tstSeq.PeekASN1Tag(asn1.Tag(1).ContextSpecific().Constructed()) {
		var extSeq cryptobyte.String
		if !tstSeq.ReadASN1(&extSeq, asn1.Tag(1).ContextSpecific().Constructed()) {
			return nil, errors.New("failed to read extensions")
		}

		for !extSeq.Empty() {
			var ext pkix.Extension
			var extBytes cryptobyte.String
			if !extSeq.ReadASN1(&extBytes, asn1.SEQUENCE) {
				return nil, errors.New("failed to read extension SEQUENCE")
			}

			if !extBytes.ReadASN1ObjectIdentifier(&ext.Id) {
				return nil, errors.New("failed to read extension OID")
			}

			// Optional critical field
			if extBytes.PeekASN1Tag(asn1.BOOLEAN) {
				if !extBytes.ReadASN1Boolean(&ext.Critical) {
					return nil, errors.New("failed to read extension critical")
				}
			}

			if !extBytes.ReadASN1Bytes(&ext.Value, asn1.OCTET_STRING) {
				return nil, errors.New("failed to read extension value")
			}

			tstInfo.Extensions = append(tstInfo.Extensions, ext)
		}
	}

	return &tstInfo, nil
}
