package secureboot

import (
	"bytes"
	"encoding/binary"
	"log"

	"github.com/foxboron/goefi/efi/attributes"
	"github.com/foxboron/goefi/efi/util"
)

// Section 32.4.1 Signature Database
// Page 1714 -> Page 1717
var (
	CERT_SHA256_GUID         = util.EFIGUID{0xc1c41626, 0x504c, 0x4092, [8]uint8{0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28}}
	CERT_RSA2048_GUID        = util.EFIGUID{0x3c5766e8, 0x269c, 0x4e34, [8]uint8{0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6}}
	CERT_RSA2048_SHA256_GUID = util.EFIGUID{0xe2b36190, 0x879b, 0x4a3d, [8]uint8{0xad, 0x8d, 0xf2, 0xe7, 0xbb, 0xa3, 0x27, 0x84}}

	CERT_SHA1_GUID         = util.EFIGUID{0x826ca512, 0xcf10, 0x4ac9, [8]uint8{0xb1, 0x87, 0xbe, 0x01, 0x49, 0x66, 0x31, 0xbd}}
	CERT_RSA2048_SHA1_GUID = util.EFIGUID{0x67f8444f, 0x8743, 0x48f1, [8]uint8{0xa3, 0x28, 0x1e, 0xaa, 0xb8, 0x73, 0x60, 0x80}}

	CERT_X509_GUID = util.EFIGUID{0xa5c059a1, 0x94e4, 0x4aa7, [8]uint8{0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}}

	CERT_SHA224_GUID = util.EFIGUID{0xb6e5233, 0xa65c, 0x44c9, [8]uint8{0x94, 0x07, 0xd9, 0xab, 0x83, 0xbf, 0xc8, 0xbd}}

	CERT_SHA384_GUID = util.EFIGUID{0xff3e5307, 0x9fd0, 0x48c9, [8]uint8{0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x01}}

	CERT_SHA512_GUID = util.EFIGUID{0x93e0fae, 0xa6c4, 0x4f50, [8]uint8{0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a}}

	CERT_X509_SHA256_GUID = util.EFIGUID{0x3bd2a492, 0x96c0, 0x4079, [8]uint8{0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed}}
)

// Quick access list
// Maybe a map[string]EFIGUID?
var ValidEFISignatureSchemes = map[util.EFIGUID]string{
	CERT_SHA256_GUID:         "SHA256",
	CERT_RSA2048_GUID:        "RSA2048",
	CERT_RSA2048_SHA256_GUID: "RSA2048, SHA256",
	CERT_SHA1_GUID:           "SHA1",
	CERT_RSA2048_SHA1_GUID:   "RSA2048 SHA1",
	CERT_X509_GUID:           "X509",
	CERT_SHA224_GUID:         "SHA224",
	CERT_SHA384_GUID:         "SHA238",
	CERT_SHA512_GUID:         "SHA512",
	CERT_X509_SHA256_GUID:    "X509 SHA256",
}

// Section 3.3 - Globally Defined Variables
// Array of GUIDs representing the type of signatures supported by
// the platform firmware. Should be treated as read-only
func GetSupportedSignatures(f *bytes.Reader) []util.EFIGUID {
	supportedSigs := make([]util.EFIGUID, f.Len()/16)
	if err := binary.Read(f, binary.LittleEndian, &supportedSigs); err != nil {
		log.Fatal(err)
	}
	return supportedSigs
}

// Section 32.4.1 - Signature Database
// Page 1712
type SignatureData struct {
	Owner util.EFIGUID
	Data  []uint8
}

func ReadSignatureData(f *bytes.Reader, size uint32) *SignatureData {
	s := SignatureData{}
	if err := binary.Read(f, binary.LittleEndian, &s.Owner); err != nil {
		log.Fatal(err)
	}
	data := make([]uint8, size-16) // Subtract the size of Owner
	if err := binary.Read(f, binary.LittleEndian, &data); err != nil {
		log.Fatal(err)
	}
	s.Data = data[:]
	return &s
}

// Section 32.4.1 - Signature Database
// Page 1713
type SignatureList struct {
	SignatureType   util.EFIGUID
	ListSize        uint32
	HeaderSize      uint32
	Size            uint32
	SignatureHeader []uint8
	Signatures      []*SignatureData
}

func ReadSignatureList(f *bytes.Reader) *SignatureList {
	s := SignatureList{}
	for _, i := range []interface{}{&s.SignatureType, &s.ListSize, &s.HeaderSize, &s.Size} {
		if err := binary.Read(f, binary.LittleEndian, i); err != nil {
			log.Fatal(err)
		}
	}
	sig, _ := ValidEFISignatureSchemes[s.SignatureType]

	var sigData []*SignatureData
	switch sig {
	case "X509":
		if s.HeaderSize != 0 {
			log.Fatalf("Unexpected HeaderSize for x509 cert. Should be 0!")
		}
		// Null out this field I guess
		s.SignatureHeader = []uint8{}
		for {
			if f.Len() == 0 {
				break
			}
			sigData = append(sigData, ReadSignatureData(f, s.Size))
		}
	default:
		log.Fatalf("Not implemented: %s", sig)
	}
	s.Signatures = sigData
	return &s
}

// Section 32.2.4 Code Defintiions
// Page. 1707
// WIN_CERTIFICATE_UEFI_GUID

// According to page 1705
// UEFI Spec February 2020
var WIN_CERTIFICATE_REVISION = 0x0200

type WINCertType uint16

// Page 1705
// 0x0EF0 to 0x0EFF is the reserved range
var (
	WIN_CERT_TYPE_PKCS_SIGNED_DATA WINCertType = 0x0002
	WIN_CERT_TYPE_EFI_PKCS115      WINCertType = 0x0EF0
	WIN_CERT_TYPE_EFI_GUID         WINCertType = 0x0EF1
)

type WINCertificate struct {
	Length          uint32
	Revision        uint16
	CertificateType WINCertType
}

var (
	EFI_CERT_TYPE_RSA2048_SHA256_GUID = util.EFIGUID{0xa7717414, 0xc616, 0x4977, [8]uint8{0x94, 0x20, 0x84, 0x47, 0x12, 0xa7, 0x35, 0xbf}}
	EFI_CERT_TYPE_PKCS7_GUID          = util.EFIGUID{0x4aafd29d, 0x68df, 0x49ee, [8]uint8{0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7}}
)

type WinCertificateUEFIGUID struct {
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
// Used when EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS is set.
type EFIVariableAuthentication2 struct {
	Time attributes.EFITime
	// AuthInfo util.EFIGUID // WIN_CERTIFICATE_UEFI_GUID
}

func ReadEFIVariableAuthencation2(f *bytes.Reader) *EFIVariableAuthentication2 {
	var efi EFIVariableAuthentication2
	if err := binary.Read(f, binary.LittleEndian, &efi); err != nil {
		log.Fatal(err)
	}
	var cert WINCertificate
	if err := binary.Read(f, binary.LittleEndian, &cert); err != nil {
		log.Fatal(err)
	}
	return &efi
}

// Page. 237
// Deprecated. But defined because #reasons
type EFIVariableAuthentication struct {
	MonotonicCount uint64
	AuthInfo       util.EFIGUID // WIN_CERTIFICATE_UEFI_GUID
}
