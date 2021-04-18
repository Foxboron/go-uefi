package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"log"
	"math/big"
	"time"
)

type SigningContext struct {
	Cert     *x509.Certificate
	Key      *rsa.PrivateKey
	SigData  []byte
	Indirect bool
}

// This code is canabalized from the mozille pkcs7 library
// and the sassoftware/relic library
// Neither did what I wanted so here we are

// OID data we need
var (
	OIDData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDDigestAlgorithmSHA256  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDEncryptionAlgorithmRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// PE/COFF signing specific
	OIDSpcIndirectDataContent = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	OIDSpcPEImageDataObjID    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
)

type IssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

func MarshalAttributes(attrs []Attribute) []byte {
	encodedAttributes, err := asn1.Marshal(struct {
		A []Attribute `asn1:"set"`
	}{A: attrs})
	if err != nil {
		panic("Couldn't marshal attributes for signing")
	}
	//For clarity: The IMPLICIT [0] tag in
	//the authenticatedAttributes field is not part of the Attributes
	//value. The Attributes value's tag is SET OF, and the DER encoding of
	//the SET OF tag, rather than of the IMPLICIT [0] tag, is to be
	//digested along with the length and contents octets of the Attributes
	//value.)
	var raw asn1.RawValue
	asn1.Unmarshal(encodedAttributes, &raw)
	return raw.Bytes
}

type SpcIndirectDataContentPe struct {
	Data struct {
		Type  asn1.ObjectIdentifier
		Value struct {
			Flags asn1.BitString
			File  struct {
				URL     string `asn1:"optional,tag:0,ia5"`
				Moniker struct {
					ClassID        []byte
					SerializedData []byte
				} `asn1:"optional,tag:1"`
				File struct {
					Unicode string `asn1:"optional,tag:0,utf8"`
					ASCII   string `asn1:"optional,tag:1,ia5"`
				} `asn1:"optional,tag:2"`
			} `asn1:"tag:0"`
		} `asn1:"optional"`
	}
	MessageDigest struct {
		DigestAlgorithm pkix.AlgorithmIdentifier
		Digest          []byte
	}
}

type contentInfo2 struct {
	ContentType asn1.ObjectIdentifier
	Value       asn1.RawValue
}

type ContentInfo struct {
	Content     asn1.RawContent
	ContentType asn1.ObjectIdentifier
}

// Unmarshal a structure from a ContentInfo.
func (ci ContentInfo) Unmarshal(dest interface{}) (err error) {
	// First re-decode the contentinfo but this time with the second field
	var ci2 contentInfo2
	_, err = asn1.Unmarshal(ci.Content, &ci2)
	if err == nil {
		// Now decode the raw value in the second field
		_, err = asn1.Unmarshal(ci2.Value.Bytes, dest)
	}
	return
}

func (ci ContentInfo) Bytes() ([]byte, error) {
	var value asn1.RawValue
	if err := ci.Unmarshal(&value); err != nil {
		if _, ok := err.(asn1.SyntaxError); ok {
			// short sequence because the value was omitted
			return nil, nil
		}
		return nil, err
	}
	return value.Bytes, nil
}

// Create a ContentInfo structure for the given bytes or structure. data can be
// nil for detached signatures.
func NewContentInfo(contentType asn1.ObjectIdentifier, data interface{}) (ci ContentInfo, err error) {
	if data == nil {
		return ContentInfo{ContentType: contentType}, nil
	}
	// There's no way to just encode the struct with the asn1.RawValue directly
	// while also supporting the ability to not emit the 2nd field for the nil
	// case, so instead this stupid dance of encoding it with the field then
	// stuffing it into Raw is necessary...
	encoded, err := asn1.Marshal(data)
	if err != nil {
		return ContentInfo{}, err
	}
	ci2 := contentInfo2{
		ContentType: contentType,
		Value: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      encoded,
		},
	}
	ciblob, err := asn1.Marshal(ci2)
	if err != nil {
		return ContentInfo{}, nil
	}
	return ContentInfo{Content: ciblob, ContentType: contentType}, nil
}

type SignedData struct {
	ContentType asn1.ObjectIdentifier
	Content     SignerData `asn1:"explicit,optional,tag:0"`
}

type RawCertificates struct {
	Raw asn1.RawContent
}

// dump raw certificates to structure
func MarshalCertificates(certs ...*x509.Certificate) RawCertificates {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	val := asn1.RawValue{Bytes: buf.Bytes(), Class: 2, Tag: 0, IsCompound: true}
	b, _ := asn1.Marshal(val)
	return RawCertificates{Raw: b}
}

type SignerData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                ContentInfo
	Certificates               RawCertificates        `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []SignerInfo           `asn1:"set"`
}

type SignerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     IssuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []Attribute `asn1:"optional,omitempty,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []Attribute `asn1:"optional,omitempty,tag:0"` // We don't use this
}

func SignData(ctx *SigningContext) []byte {

	// This made me wtf.
	// The message digest is not the content we wan't signed when doing authenticode
	// We want to sign the entire indirect object, which contains the sums
	var messageDigest []byte
	var ci ContentInfo
	if ctx.Indirect {
		var indirect SpcIndirectDataContentPe
		indirect.Data.Type = OIDSpcPEImageDataObjID
		sum := sha256.Sum256(ctx.SigData)
		indirect.MessageDigest.Digest = sum[:]
		indirect.MessageDigest.DigestAlgorithm = pkix.AlgorithmIdentifier{Algorithm: OIDDigestAlgorithmSHA256,
			Parameters: asn1.NullRawValue}
		indirect.Data.Value.File.File.Unicode = string([]byte{0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x4f, 0x00, 0x62,
			0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x74,
			0x00, 0x65, 0x00, 0x3e, 0x00, 0x3e, 0x00, 0x3E})
		ci, _ = NewContentInfo(OIDSpcIndirectDataContent, indirect)
		buf, err := ci.Bytes()
		if err != nil {
			log.Fatal(err)
		}
		sum = sha256.Sum256(buf)
		messageDigest = sum[:]
	} else {
		ci, _ = NewContentInfo(OIDData, nil)
		sum := sha256.Sum256(ctx.SigData)
		messageDigest = sum[:]
	}

	h := sha256.New()
	var attr []Attribute
	for _, v := range []struct {
		Type  asn1.ObjectIdentifier
		Value interface{}
	}{
		{
			Type:  OIDAttributeContentType,
			Value: ci.ContentType,
		},
		{
			Type:  OIDAttributeSigningTime,
			Value: time.Now().UTC(),
		},
		{
			Type:  OIDAttributeMessageDigest,
			Value: messageDigest[:],
		},
	} {
		asn1Value, err := asn1.Marshal(v.Value)
		if err != nil {
			log.Fatal(err)
		}
		attr = append(attr, Attribute{
			Type:  v.Type,
			Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: asn1Value}, // 17 == SET tag
		})
	}
	h.Write(MarshalAttributes(attr))

	sig, err := ctx.Key.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}
	s := SignerInfo{
		Version: 1,
		IssuerAndSerialNumber: IssuerAndSerial{
			SerialNumber: ctx.Cert.SerialNumber,
			IssuerName:   asn1.RawValue{FullBytes: ctx.Cert.RawIssuer},
		},
		AuthenticatedAttributes:   attr,
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: OIDDigestAlgorithmSHA256, Parameters: asn1.NullRawValue},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: OIDEncryptionAlgorithmRSA, Parameters: asn1.NullRawValue},
		EncryptedDigest:           sig,
	}

	ss := SignerData{
		Version:                    1,
		DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{{Algorithm: OIDDigestAlgorithmSHA256, Parameters: asn1.NullRawValue}},
		ContentInfo:                ci,
		Certificates:               MarshalCertificates(ctx.Cert),
		CRLs:                       nil,
		SignerInfos:                []SignerInfo{s},
	}

	if ctx.Indirect {
		Payload := SignedData{
			ContentType: OIDSignedData,
			Content:     ss,
		}
		b, err := asn1.Marshal(Payload)
		if err != nil {
			log.Fatal(err)
		}
		return b
	} else {
		b, err := asn1.Marshal(ss)
		if err != nil {
			log.Fatal(err)
		}
		return b
	}
}

func ParseSignature(buf []byte) *SignedData {
	var payload SignedData
	if _, err := asn1.Unmarshal(buf, &payload); err != nil {
		log.Fatal(err)
	}
	return &payload
}

func VerifySignature(cert *x509.Certificate, buf []byte) (bool, error) {
	payload := ParseSignature(buf)
	for _, si := range payload.Content.SignerInfos {
		sigData := MarshalAttributes(si.AuthenticatedAttributes)
		err := cert.CheckSignature(x509.SHA256WithRSA, sigData, si.EncryptedDigest)
		if errors.Is(err, rsa.ErrVerification) {
			continue
		} else if errors.Is(err, rsa.ErrDecryption) {
			continue
		} else if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}
