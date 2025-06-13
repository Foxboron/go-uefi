package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	encasn1 "encoding/asn1"
)

// OID data we need
var (
	OIDData                   = encasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData             = encasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDDigestAlgorithmSHA256  = encasn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDEncryptionAlgorithmRSA = encasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDAttributeContentType   = encasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDAttributeMessageDigest = encasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDAttributeSigningTime   = encasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

var (
	ErrNoCertificate = errors.New("no valid certificates")
)

type Config struct {
	NoAttr  bool
	NoCerts bool
}

type Option func(*Config)

func NoAttr() Option {
	return func(c *Config) {
		c.NoAttr = true
	}
}

func NoCerts() Option {
	return func(c *Config) {
		c.NoCerts = true
	}
}

// Partially implements RFC2315
func SignPKCS7(signer crypto.Signer, cert *x509.Certificate, oid encasn1.ObjectIdentifier, content []byte, opts ...Option) ([]byte, error) {
	config := &Config{}
	for _, optFunc := range opts {
		optFunc(config)
	}

	var contentInfo cryptobyte.Builder

	h := crypto.SHA256.New()
	h.Write(content)

	var attributes []byte
	if !config.NoAttr {
		// Hash authenticated attributes
		// TODO, not needed for Wincert/UEFI. But we do it anyway
		// Original Implementation has:
		// - OIDAttributeContentType
		// - OIDAttributeSigningTime
		// - OIDAttributeMessageDigest
		attrs := &Attributes{
			ContentType:   oid,
			MessageDigest: h.Sum(nil),
			SigningTime:   time.Now().UTC(),
		}
		attributes = attrs.Marshal()
		h = crypto.SHA256.New()
		h.Write(attributes)
	}

	sig, err := signer.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}

	// ContentInfo ::= SEQUENCE
	contentInfo.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {

		// contentType ContentType,
		b.AddASN1ObjectIdentifier(OIDSignedData)

		// content [0] EXPLICIT DEFINED BY contentType OPTIONAL
		b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {

			// SignedData ::= SEQUENCE
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {

				// version Version,
				b.AddASN1Int64(1)

				// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
				// digestAlgorithms DigestAlgorithmIdentifiers,
				b.AddASN1(asn1.SET, func(b *cryptobyte.Builder) {
					// AlgorithmIdentifier  ::=  SEQUENCE
					b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
						//   algorithm               OBJECT IDENTIFIER,
						// NOTE: Only sha256 hardcoded atm
						b.AddASN1ObjectIdentifier(OIDDigestAlgorithmSHA256)
						//   parameters              ANY DEFINED BY algorithm OPTIONAL
						b.AddASN1NULL()
					})
				})

				// contentInfo ContentInfo
				// ContentInfo ::= SEQUENCE
				b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {

					// contentType ContentType
					b.AddASN1ObjectIdentifier(oid)

					// content [0] EXPLICIT DEFINED BY contentType OPTIONAL
					if len(content) > 0 && !oid.Equal(OIDData) {
						b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
							b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
								b.AddBytes(content)
							})
						})
					}
				})

				if !config.NoCerts {
					// certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL
					b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						// b.AddBytes(signer.Raw)
						b.AddBytes(cert.Raw)
					})
				}

				// Not Used
				// crls [1] IMPLICIT CertificateRevocationLists OPTIONAL

				// signerInfos SignerInfos
				// SignerInfos ::= SET OF SignerInfo
				// We only have one in Authenticode
				b.AddASN1(asn1.SET, func(b *cryptobyte.Builder) {
					// SignerInfo ::= SEQUENCE
					b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
						// version Version,
						b.AddASN1Int64(1)

						// issuerAndSerialNumber IssuerAndSerialNumber
						// IssuerAndSerialNumber ::= SEQUENCE
						b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
							// issuer Name
							b.AddBytes(cert.RawIssuer)
							// serialNumber CertificateSerialNumber
							b.AddASN1BigInt(cert.SerialNumber)
						})

						// digestAlgorithm DigestAlgorithmIdentifier
						b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
							//   algorithm               OBJECT IDENTIFIER,
							// NOTE: Only sha256 hardcoded atm
							b.AddASN1ObjectIdentifier(OIDDigestAlgorithmSHA256)
							//   parameters              ANY DEFINED BY algorithm OPTIONAL
							b.AddASN1NULL()
						})

						if !config.NoAttr {
							// authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL
							b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
								attrsOuter := cryptobyte.String(attributes)
								var attrsInner cryptobyte.String
								attrsOuter.ReadASN1(&attrsInner, asn1.SET)
								b.AddBytes(attrsInner)
							})
						}

						// digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier
						b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
							//   algorithm               OBJECT IDENTIFIER,
							b.AddASN1ObjectIdentifier(OIDEncryptionAlgorithmRSA)
							//   parameters              ANY DEFINED BY algorithm OPTIONAL
							b.AddASN1NULL()
						})

						// encryptedDigest EncryptedDigest
						b.AddASN1OctetString(sig)

						// unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL
						// Not used
					})
				})
			})
		})
	})

	return contentInfo.Bytes()
}

// Parse cryptobyte string to pkix.AlgorithmIdentifier
func ParseAlgorithmIdentifier(der *cryptobyte.String) (*pkix.AlgorithmIdentifier, error) {
	var ident pkix.AlgorithmIdentifier
	var s cryptobyte.String

	if !der.ReadASN1(&s, asn1.SEQUENCE) {
		return nil, errors.New("no algorithmidentifier")
	}

	if !s.ReadASN1ObjectIdentifier(&ident.Algorithm) {
		return nil, errors.New("missing missing algorithmIdentifier")
	}

	if s.Empty() {
		return &ident, nil
	}

	var asn1Null cryptobyte.String
	if !s.ReadASN1(&asn1Null, asn1.NULL) {
		return nil, errors.New("missing missing algorithmIdentifier")
	}
	// TODO: Support paramters, we don't use it currently
	return &ident, nil
}

func hasContentInfo(der *cryptobyte.String) (bool, error) {
	check := *der
	if !check.ReadASN1(&check, asn1.SEQUENCE) {
		return false, errors.New("incorrect input")
	}
	if !check.PeekASN1Tag(asn1.OBJECT_IDENTIFIER) {
		return false, nil
	}
	return true, nil
}

func ParseContentInfo(der *cryptobyte.String) (oid encasn1.ObjectIdentifier, content cryptobyte.String, err error) {
	var s cryptobyte.String

	if !der.ReadASN1(&s, asn1.SEQUENCE) {
		return nil, nil, errors.New("no contentinfo")
	}

	if !s.ReadASN1ObjectIdentifier(&oid) {
		return nil, nil, errors.New("no contentinfo oid")
	}

	if !s.ReadOptionalASN1(&content, nil, asn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, nil, errors.New("no contentinfo content")
	}

	return
}

func parseCertificates(der *cryptobyte.String) ([]*x509.Certificate, error) {
	var raw cryptobyte.String
	if !der.ReadOptionalASN1(&raw, nil, asn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, errors.New("no certificates")
	}
	certs, err := x509.ParseCertificates(raw)
	if err != nil {
		return nil, fmt.Errorf("failed parsing certificates: %v", err)
	}
	return certs, nil
}

type issuerAndSerialNumber struct {
	RawIssuer    []byte
	SerialNumber *big.Int
}

func parseIssuerAndSerialNumber(der *cryptobyte.String) (*issuerAndSerialNumber, error) {
	// TODO: We don't really use it yet. Expose error
	var s cryptobyte.String
	var ias issuerAndSerialNumber
	var bi big.Int

	var issuer cryptobyte.String

	if !der.ReadASN1(&s, asn1.SEQUENCE) {
		return nil, errors.New("no issuer and serial number")
	}
	if !s.ReadASN1Element(&issuer, asn1.SEQUENCE) {
		return nil, errors.New("not a raw issuer")
	}
	ias.RawIssuer = issuer
	if !s.ReadASN1Integer(&bi) {
		return nil, errors.New("no serial number")
	}
	ias.SerialNumber = &bi
	return &ias, nil
}

func parseAttributes(der *cryptobyte.String) (*Attributes, error) {
	var attributes Attributes
	var attrs cryptobyte.String
	var hasAttrs bool

	if !der.ReadOptionalASN1(&attrs, &hasAttrs, asn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, errors.New("malformed attributes")
	}

	if !hasAttrs {
		return nil, nil
	}

	var contentType cryptobyte.String
	var contentOID encasn1.ObjectIdentifier

	for !attrs.Empty() {
		if !attrs.ReadASN1(&contentType, asn1.SEQUENCE) {
			return nil, errors.New("malformed content type")
		}

		if !contentType.ReadASN1ObjectIdentifier(&contentOID) {
			return nil, errors.New("malformed content type oid")
		}

		if !contentType.ReadASN1(&contentType, asn1.SET) {
			return nil, errors.New("content type set")
		}

		switch {
		case contentOID.Equal(OIDAttributeMessageDigest):
			var digest cryptobyte.String
			if !contentType.ReadASN1(&digest, asn1.OCTET_STRING) {
				return nil, errors.New("could not parse message digest")
			}
			attributes.MessageDigest = digest
		case contentOID.Equal(OIDAttributeContentType):
			var contentTypeOID encasn1.ObjectIdentifier
			if !contentType.ReadASN1ObjectIdentifier(&contentTypeOID) {
				return nil, errors.New("could not parse Content Type")
			}
			attributes.ContentType = contentTypeOID
		case contentOID.Equal(OIDAttributeSigningTime):
			if !contentType.ReadASN1UTCTime(&attributes.SigningTime) {
				return nil, errors.New("could not parse Signing Time")
			}
		default:
			// Save the bytes for any attributes we are not parsing.
			attributes.Other = append(attributes.Other, &unparsedAttribute{
				Type:  contentOID,
				Bytes: contentType,
			})
		}
	}
	return &attributes, nil
}

func parseEncryptedDigest(der *cryptobyte.String) ([]byte, error) {
	var encryptedDigest cryptobyte.String
	if !der.ReadASN1(&encryptedDigest, asn1.OCTET_STRING) {
		return nil, errors.New("malfomed encrypted digest")
	}
	return encryptedDigest, nil
}

func parseSignerInfos(der *cryptobyte.String) (*signerinfo, error) {
	var signerInfo cryptobyte.String
	var si signerinfo

	if !der.ReadASN1(&signerInfo, asn1.SEQUENCE) {
		return nil, errors.New("no signer info")
	}

	var version int64
	if !signerInfo.ReadASN1Integer(&version) {
		return nil, errors.New("no version")
	}
	si.Version = version

	ias, err := parseIssuerAndSerialNumber(&signerInfo)
	if err != nil {
		return nil, fmt.Errorf("failed parsing issuer and serial number: %v", err)
	}
	si.IssuerAndSerialnumber = ias

	//digestAlgo
	algid, err := ParseAlgorithmIdentifier(&signerInfo)
	if err != nil {
		return nil, fmt.Errorf("failed parsing digest algorithm: %v", err)
	}
	si.DigestAlgorithm = algid

	//attributes
	attrs, err := parseAttributes(&signerInfo)
	if err != nil {
		return nil, fmt.Errorf("failed parsing attributes: %v", err)
	}
	si.AuthenticatedAttributes = attrs

	// digest encrypted algorithm
	algid, err = ParseAlgorithmIdentifier(&signerInfo)
	if err != nil {
		return nil, fmt.Errorf("failed parsing encrypted digest algorithm: %v", err)
	}
	si.EncryptedDigestAlgorithm = algid

	digest, err := parseEncryptedDigest(&signerInfo)
	if err != nil {
		return nil, fmt.Errorf("failed parsing encrypted digest: %v", err)
	}
	si.EncryptedDigest = digest

	return &si, nil
}

type signerinfo struct {
	Version                  int64
	EncryptedDigest          []byte
	DigestAlgorithm          *pkix.AlgorithmIdentifier
	AuthenticatedAttributes  *Attributes
	EncryptedDigestAlgorithm *pkix.AlgorithmIdentifier
	IssuerAndSerialnumber    *issuerAndSerialNumber
}

func (s *signerinfo) verify(cert *x509.Certificate) (bool, error) {
	sigdata := s.AuthenticatedAttributes.Marshal()
	err := cert.CheckSignature(x509.SHA256WithRSA, sigdata, s.EncryptedDigest)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *signerinfo) isCertificate(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawIssuer, s.IssuerAndSerialnumber.RawIssuer) {
		return false
	}
	if cert.SerialNumber.Cmp(s.IssuerAndSerialnumber.SerialNumber) != 0 {
		return false
	}
	return true
}

type PKCS7 struct {
	OID                 encasn1.ObjectIdentifier
	SignerInfo          []*signerinfo
	ContentInfo         []byte
	Certs               []*x509.Certificate
	AlgorithmIdentifier *pkix.AlgorithmIdentifier
}

func (p *PKCS7) Verify(cert *x509.Certificate) (bool, error) {
	for _, si := range p.SignerInfo {
		if !si.isCertificate(cert) {
			continue
		}
		ok, err := si.verify(cert)
		if err != nil {
			return false, fmt.Errorf("failed validating signature: %w", err)
		}
		if !ok {
			continue
		}
		return true, nil
	}
	return false, nil
}

func (p *PKCS7) HasCertificate(cert *x509.Certificate) bool {
	for _, si := range p.SignerInfo {
		if si.isCertificate(cert) {
			return true
		}
	}
	return false
}

func ParsePKCS7(b []byte) (*PKCS7, error) {
	var pkcs PKCS7

	contentInfo := cryptobyte.String(b)

	var oid encasn1.ObjectIdentifier
	if ok, err := hasContentInfo(&contentInfo); ok {
		oid, contentInfo, err = ParseContentInfo(&contentInfo)
		if err != nil {
			return nil, fmt.Errorf("failed parsing contenting info: %v", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("failed checking content info: %v", err)
	}

	pkcs.OID = oid

	var signedData cryptobyte.String
	if !contentInfo.ReadASN1(&signedData, asn1.SEQUENCE) {
		return nil, errors.New("no signed data")
	}

	var version int64
	if !signedData.ReadASN1Integer(&version) {
		return nil, errors.New("no version")
	}

	var digest cryptobyte.String
	if !signedData.ReadASN1(&digest, asn1.SET) {
		return nil, errors.New("no digest crypto")
	}

	algid, err := ParseAlgorithmIdentifier(&digest)
	if err != nil {
		return nil, fmt.Errorf("failed algorithm identifier: %v", err)
	}
	pkcs.AlgorithmIdentifier = algid

	oid, content, err := ParseContentInfo(&signedData)
	if err != nil {
		return nil, fmt.Errorf("failed parsing content info: %v", err)
	}
	pkcs.OID = oid
	pkcs.ContentInfo = content

	certs, err := parseCertificates(&signedData)
	if err != nil {
		return nil, fmt.Errorf("failed parsing certificates: %v", err)
	}
	pkcs.Certs = certs

	var signerInfo cryptobyte.String

	if !signedData.ReadASN1(&signerInfo, asn1.SET) {
		return nil, errors.New("no signer info")
	}
	for !signerInfo.Empty() {
		si, err := parseSignerInfos(&signerInfo)
		if err != nil {
			return nil, fmt.Errorf("failed parsing signer info: %v", err)
		}
		pkcs.SignerInfo = append(pkcs.SignerInfo, si)
	}

	return &pkcs, nil
}

type unparsedAttribute struct {
	Type  encasn1.ObjectIdentifier
	Bytes []byte
}

type Attributes struct {
	ContentType   encasn1.ObjectIdentifier
	MessageDigest []byte
	SigningTime   time.Time
	Other         []*unparsedAttribute
}

func (a *Attributes) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	// Attributes := SET OF Attribute
	b.AddASN1(asn1.SET, func(b *cryptobyte.Builder) {
		// Add the content type
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(OIDAttributeContentType)
			b.AddASN1(asn1.SET, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(a.ContentType)
			})
		})
		if !a.SigningTime.IsZero() {
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(OIDAttributeSigningTime)
				b.AddASN1(asn1.SET, func(b *cryptobyte.Builder) {
					b.AddASN1UTCTime(a.SigningTime)
				})
			})
		}
		// Digest from Authenticode
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(OIDAttributeMessageDigest)
			b.AddASN1(asn1.SET, func(b *cryptobyte.Builder) {
				b.AddASN1OctetString(a.MessageDigest)
			})
		})
		for _, attr := range a.Other {
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(attr.Type)
				b.AddASN1(asn1.SET, func(b *cryptobyte.Builder) {
					b.AddBytes(attr.Bytes)
				})
			})
		}
	})
	return b.BytesOrPanic()
}
