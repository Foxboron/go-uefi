package signature

import (
	"bytes"
	"encoding/binary"
	"log"

	"github.com/foxboron/go-uefi/efi/util"
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

func ReadWinCertificate(f *bytes.Reader) (WINCertificate, error) {
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

const SizeofWinCertificateUEFIGUID = SizeofWINCertificate + 16

func ReadWinCertificateUEFIGUID(f *bytes.Reader) (WinCertificateUEFIGUID, error) {
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

func ReadEFIVariableAuthencation2(f *bytes.Reader) (*EFIVariableAuthentication2, error) {
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
