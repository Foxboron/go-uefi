package signature

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"io"
	"log"

	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/efivar"
	"golang.org/x/crypto/cryptobyte"

	"github.com/foxboron/go-uefi/pkcs7"
	"github.com/pkg/errors"
)

// Section 32.2.4 Code Defintiions
// Page. 1707
// WIN_CERTIFICATE_UEFI_GUID

// According to page 1705
// UEFI Spec February 2020
var WIN_CERTIFICATE_REVISION uint16 = 0x0200

type WINCertType uint16

// Page 1705
// 0x0EF0 to 0x0EFF is the reserved range
var (
	WIN_CERT_TYPE_PKCS_SIGNED_DATA WINCertType = 0x0002
	WIN_CERT_TYPE_EFI_PKCS1_15     WINCertType = 0x0EF0
	WIN_CERT_TYPE_EFI_GUID         WINCertType = 0x0EF1
)

var WINCertTypeString = map[WINCertType]string{
	0x0002: "WIN_CERT_TYPE_PKCS_SIGNED_DATA",
	0x0EF0: "WIN_CERT_TYPE_EFI_PKCS1_15",
	0x0EF1: "WIN_CERT_TYPE_EFI_GUID",
}

// PE/COFF structure for signing
// Page 1705
type WINCertificate struct {
	Length      uint32
	Revision    uint16
	CertType    WINCertType
	Certificate []uint8
}

const SizeofWINCertificate = 4 + 2 + 2

var ErrParse = errors.New("could not parse struct")

func ReadWinCertificate(f io.Reader) (WINCertificate, error) {
	var cert WINCertificate
	for _, v := range []interface{}{&cert.Length, &cert.Revision, &cert.CertType} {
		if err := binary.Read(f, binary.LittleEndian, v); err != nil {
			return WINCertificate{}, errors.Wrapf(err, "could not parse WINCertificate")
		}
	}
	if cert.Revision != WIN_CERTIFICATE_REVISION {
		return WINCertificate{}, errors.Wrapf(ErrParse, "WINCertificate revision should be %x, but is %x. Malformed or invalid", WIN_CERTIFICATE_REVISION, cert.Revision)
	}
	certLength := make([]byte, cert.Length-SizeofWINCertificate)
	if err := binary.Read(f, binary.LittleEndian, certLength); err != nil {
		return WINCertificate{}, errors.Wrapf(err, "could not get signature data")
	}
	cert.Certificate = certLength[:]
	return cert, nil
}

func WriteWinCertificate(b *bytes.Buffer, w *WINCertificate) {
	for _, d := range []interface{}{w.Length, w.Revision, w.CertType, w.Certificate} {
		if err := binary.Write(b, binary.LittleEndian, d); err != nil {
			log.Fatal(err)
		}
	}
}

var (
	EFI_CERT_TYPE_RSA2048_SHA256_GUID = util.EFIGUID{0xa7717414, 0xc616, 0x4977, [8]uint8{0x94, 0x20, 0x84, 0x47, 0x12, 0xa7, 0x35, 0xbf}}
	EFI_CERT_TYPE_PKCS7_GUID          = util.EFIGUID{0x4aafd29d, 0x68df, 0x49ee, [8]uint8{0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7}}
)

// Should implement an interface
// Page 1707
type WinCertificateUEFIGUID struct {
	Header   WINCertificate
	CertType util.EFIGUID // One of the EFI_CERT types
	CertData []uint8
}

const SizeofWinCertificateUEFIGUID = SizeofWINCertificate + util.SizeofEFIGUID

func ReadWinCertificateUEFIGUID(f io.Reader) (WinCertificateUEFIGUID, error) {
	var cert WinCertificateUEFIGUID
	hdr, err := ReadWinCertificate(f)
	if err != nil {
		return WinCertificateUEFIGUID{}, errors.Wrap(err, "could not parse WINCert UEFI_GUID")
	}
	cert.Header = hdr
	reader := bytes.NewBuffer(cert.Header.Certificate)
	if err := binary.Read(reader, binary.LittleEndian, &cert.CertType); err != nil {
		log.Fatal(err)
	}
	rbuf := make([]byte, reader.Len())
	if err := binary.Read(reader, binary.LittleEndian, rbuf); err != nil {
		log.Fatal(err)
	}
	cert.CertData = rbuf[:]
	return cert, nil
}

func WriteWinCertificateUEFIGUID(b *bytes.Buffer, w *WinCertificateUEFIGUID) {
	WriteWinCertificate(b, &w.Header)
	if err := binary.Write(b, binary.LittleEndian, w.CertType); err != nil {
		log.Fatal(err)
	}
	if err := binary.Write(b, binary.LittleEndian, w.CertData); err != nil {
		log.Fatal(err)
	}
}

// Page. 238
// Only used when EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS is set
type EFIVariableAuthentication3 struct {
	Version      uint8
	Type         uint8
	MetadataSize uint32
	Flags        uint32
}

// Page. 238
// Only accepts the CertType EFI_CERT_TYPE_PKCS7_GUID
type EFIVariableAuthentication2 struct {
	Time     util.EFITime
	AuthInfo WinCertificateUEFIGUID
}

// Returns an EFIVariableAuthencation2 struct
// no SignedData
func NewEFIVariableAuthentication2() *EFIVariableAuthentication2 {
	return &EFIVariableAuthentication2{
		Time: *util.NewEFITime(),
		AuthInfo: WinCertificateUEFIGUID{
			Header: WINCertificate{
				Length:   SizeofWinCertificateUEFIGUID,
				Revision: WIN_CERTIFICATE_REVISION,
				CertType: WIN_CERT_TYPE_EFI_GUID,
			},
			CertType: EFI_CERT_TYPE_PKCS7_GUID,
		},
	}
}

func (e *EFIVariableAuthentication2) Marshal(b *bytes.Buffer) {
	WriteEFIVariableAuthencation2(b, *e)
}

func (e *EFIVariableAuthentication2) Unmarshal(b *bytes.Buffer) error {
	auth, err := ReadEFIVariableAuthencation2(b)
	if err != nil {
		return err
	}
	*e = *auth
	return nil
}

func (e *EFIVariableAuthentication2) Verify(cert *x509.Certificate) (bool, error) {
	signature, err := pkcs7.ParsePKCS7(e.AuthInfo.CertData)
	if err != nil {
		return false, err
	}
	return signature.Verify(cert)
}

// We should maybe not duplicate this
type efibytes bytes.Buffer

func (e efibytes) Marshal(b *bytes.Buffer) {
	if _, err := io.Copy(b, (*bytes.Buffer)(&e)); err != nil {
		return
	}
}

func SignEFIVariable(v efivar.Efivar, m efivar.Marshallable, key crypto.Signer, cert *x509.Certificate) (*EFIVariableAuthentication2, efivar.Marshallable, error) {
	authvar := NewEFIVariableAuthentication2()

	// Bytes of the signaturedatabase (probably)
	var sb bytes.Buffer

	// Buffer for the bytes we are signing
	var buf bytes.Buffer

	s := []byte{}
	for _, n := range []byte(v.Name) {
		s = append(s, n, 0x00)
	}

	// Marshal the bytes so we can include them in for our signed data
	m.Marshal(&sb)

	writeOrder := []interface{}{
		s,
		*v.GUID,
		v.Attributes,
		authvar.Time,
		sb.Bytes(),
	}
	for _, d := range writeOrder {
		if err := binary.Write(&buf, binary.LittleEndian, d); err != nil {
			log.Fatal(err)
		}
	}

	h := crypto.SHA256.New()
	h.Write(buf.Bytes())

	der, err := pkcs7.SignPKCS7(key, cert, pkcs7.OIDData, h.Sum(nil))
	if err != nil {
		return nil, nil, err
	}

	// We need to unwrap the outer ContentInfo layer
	cs := cryptobyte.String(der)
	_, signature, err := pkcs7.ParseContentInfo(&cs)
	if err != nil {
		return nil, nil, err
	}

	authvar.AuthInfo.Header.Length += uint32(len(signature))
	authvar.AuthInfo.CertData = signature

	// Create a marshallable variable we can give to WriteVar
	// Wrapper which contains the Auth header with the Marshallable bytes behind
	var auth efibytes
	authvar.Marshal((*bytes.Buffer)(&auth))
	m.Marshal((*bytes.Buffer)(&auth))

	return authvar, auth, nil
}

func ReadEFIVariableAuthencation2(f io.Reader) (*EFIVariableAuthentication2, error) {
	var efi EFIVariableAuthentication2
	if err := binary.Read(f, binary.LittleEndian, &efi.Time); err != nil {
		log.Fatal(err)
	}
	authinfo, err := ReadWinCertificateUEFIGUID(f)
	if err != nil {
		return &EFIVariableAuthentication2{}, errors.Wrap(err, "could not parse WINCertificate UEFI_GUID")
	}
	efi.AuthInfo = authinfo
	if efi.AuthInfo.Header.CertType != WIN_CERT_TYPE_EFI_GUID {
		log.Fatalf("EFI_VARIABLE_AUTHENTICATION2 accepts only CertType WIN_CERT_TYPE_EFI_GUID. Got: %x", efi.AuthInfo.CertType)
	}
	return &efi, nil
}

func WriteEFIVariableAuthencation2(b *bytes.Buffer, e EFIVariableAuthentication2) {
	if err := binary.Write(b, binary.LittleEndian, e.Time); err != nil {
		log.Fatal(err)
	}
	WriteWinCertificateUEFIGUID(b, &e.AuthInfo)
}

// Page. 237
// Deprecated. But defined because #reasons
type EFIVariableAuthentication struct {
	MonotonicCount uint64
	AuthInfo       util.EFIGUID // WIN_CERTIFICATE_UEFI_GUID
}
