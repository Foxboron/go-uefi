package signature

import (
	"bytes"
	"encoding/binary"
	"log"

	"github.com/foxboron/goefi/efi/util"
	"go.mozilla.org/pkcs7"
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
	WIN_CERT_TYPE_EFI_PKCS115      WINCertType = 0x0EF0
	WIN_CERT_TYPE_EFI_GUID         WINCertType = 0x0EF1
)

type WINCertificate struct {
	Length    uint32
	Revision  uint16
	CertType  WINCertType
	Signature []byte
}

func ReadWinCertificate(f *bytes.Reader) *WINCertificate {
	var cert WINCertificate

	for _, v := range []interface{}{&cert.Length, &cert.Revision, &cert.CertType} {
		if err := binary.Read(f, binary.LittleEndian, v); err != nil {
			log.Fatal(err)
		}
	}
	if cert.Revision != WIN_CERTIFICATE_REVISION {
		log.Fatalf("WINCertificate revision should be %x, but is %x. Malformed or invalid", WIN_CERTIFICATE_REVISION, cert.Revision)
	}
	switch cert.CertType {
	case WIN_CERT_TYPE_EFI_GUID:
		certificateData := ReadWinCertificateUEFIGUID(f)
		if util.CmpEFIGUID(certificateData.CertType, EFI_CERT_TYPE_PKCS7_GUID) {
			signatureData := make([]byte, f.Len())
			if err := binary.Read(f, binary.LittleEndian, signatureData); err != nil {
				log.Fatal(err)
			}
			cert.Signature = signatureData[:]
			return &cert
		}
		if util.CmpEFIGUID(certificateData.CertType, EFI_CERT_TYPE_RSA2048_SHA256_GUID) {
			return &cert
		}
		log.Fatalf("Unexpected CertType from WIN_CERT_TYPE_EFI_GUID: %s", certificateData.CertType.Format())
	default:
		log.Panicf("Not implemented WINCertificate type %x", cert.CertType)
	}
	return &cert
}

var (
	EFI_CERT_TYPE_RSA2048_SHA256_GUID = util.EFIGUID{0xa7717414, 0xc616, 0x4977, [8]uint8{0x94, 0x20, 0x84, 0x47, 0x12, 0xa7, 0x35, 0xbf}}
	EFI_CERT_TYPE_PKCS7_GUID          = util.EFIGUID{0x4aafd29d, 0x68df, 0x49ee, [8]uint8{0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7}}
)

// Should implement an interface
type WinCertificateUEFIGUID struct {
	Header   WINCertificate
	CertType util.EFIGUID // One of the EFI_CERT types
}

func ReadWinCertificateUEFIGUID(f *bytes.Reader) *WinCertificateUEFIGUID {
	var cert WinCertificateUEFIGUID
	if err := binary.Read(f, binary.LittleEndian, &cert.CertType); err != nil {
		log.Fatal(err)
	}
	return &cert
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
type EFIVariableAuthentication2 struct {
	Time     util.EFITime
	AuthInfo *WINCertificate
}

func ReadEFIVariableAuthencation2(f *bytes.Reader) *EFIVariableAuthentication2 {
	var efi EFIVariableAuthentication2
	if err := binary.Read(f, binary.LittleEndian, &efi.Time); err != nil {
		log.Fatal(err)
	}
	efi.AuthInfo = ReadWinCertificate(f)
	if efi.AuthInfo.CertType != WIN_CERT_TYPE_EFI_GUID {
		log.Fatalf("EFI_VARIABLE_AUTHENTICATION2 accepts only CertType WIN_CERT_TYPE_EFI_GUID. Got: %x", efi.AuthInfo.CertType)
	}
	_, err := pkcs7.NewSignedData(efi.AuthInfo.Signature)
	// cert, err := pkcs7.Parse(efi.AuthInfo.Signature)
	if err != nil {
		log.Fatal(err)
	}
	// ioutil.WriteFile("test.der", efi.AuthInfo.Signature, 0644)
	return &efi
}

// Page. 237
// Deprecated. But defined because #reasons
type EFIVariableAuthentication struct {
	MonotonicCount uint64
	AuthInfo       util.EFIGUID // WIN_CERTIFICATE_UEFI_GUID
}
