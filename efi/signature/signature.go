package signature

import (
	"bytes"
	"encoding/binary"
	"log"

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

type CertType string

// Quick access list
// Maybe a map[string]EFIGUID?
var ValidEFISignatureSchemes = map[util.EFIGUID]CertType{
	CERT_SHA256_GUID:         "SHA256",
	CERT_RSA2048_GUID:        "RSA2048",
	CERT_RSA2048_SHA256_GUID: "RSA2048 SHA256",
	CERT_SHA1_GUID:           "SHA1",
	CERT_RSA2048_SHA1_GUID:   "RSA2048 SHA1",
	CERT_X509_GUID:           "X509",
	CERT_SHA224_GUID:         "SHA224",
	CERT_SHA384_GUID:         "SHA238",
	CERT_SHA512_GUID:         "SHA512",
	CERT_X509_SHA256_GUID:    "X509 SHA256",
}

const (
	CERT_SHA256         CertType = "SHA256"
	CERT_RSA2048                 = "RSA2048"
	CERT_RSA2048_SHA256          = "RSA2048 SHA256"
	CERT_SHA1                    = "SHA1"
	CERT_RSA2048_SHA1            = "RSA2048 SHA1"
	CERT_X509                    = "X509"
	CERT_SHA224                  = "SHA224"
	CERT_SHA384                  = "SHA238"
	CERT_SHA512                  = "SHA512"
	CERT_X509_SHA256             = "X509 SHA256"
)

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
		log.Fatalf("Couldn't read Signature Data: %s", err)
	}
	data := make([]uint8, size-16) // Subtract the size of Owner
	if err := binary.Read(f, binary.LittleEndian, &data); err != nil {
		log.Fatalf("Couldn't read Signature Data: %s", err)
	}
	s.Data = data[:]
	return &s
}

func WriteSignatureData(b *bytes.Buffer, s SignatureData) {
	for _, v := range []interface{}{s.Owner, s.Data} {
		err := binary.Write(b, binary.LittleEndian, v)
		if err != nil {
			log.Fatalf("Couldn't write signature data: %s", err)
		}
	}
}

// Section 32.4.1 - Signature Database
// Page 1713
type SignatureList struct {
	SignatureType   util.EFIGUID
	ListSize        uint32          // Total size of the signature list, including this header
	HeaderSize      uint32          // Size of SignatureHead
	Size            uint32          // Size of each signature. At least the size of EFI_SIGNATURE_DATA
	SignatureHeader []uint8         // SignatureType defines the content of this header
	Signatures      []SignatureData // SignatureData List
}

// SignatureSize + sizeof(SignatureType) + sizeof(uint32)*4
const SizeofSignatureList uint32 = 16 + 4 + 4 + 4

func NewSignatureList(data []byte, owner util.EFIGUID, certtype CertType) *SignatureList {
	sl := SignatureList{}
	switch certtype {
	case CERT_X509:
		// TODO: We should probably accept a slice...
		sl.SignatureType = CERT_X509_GUID
		sl.HeaderSize = 0
		sl.SignatureHeader = []uint8{}
		sl.Size = uint32(len(data)) + 16
		sd := []SignatureData{SignatureData{Owner: owner, Data: data}}
		sl.Signatures = sd
		// SignatureSize + sizeof(SignatureType) + sizeof(uint32)*4
		sl.ListSize = sl.Size + SizeofSignatureList
	default:
		log.Fatalf("Unsupported certificate format")
	}
	return &sl
}

func WriteSignatureList(b *bytes.Buffer, s SignatureList) {
	for _, v := range []interface{}{s.SignatureType, s.ListSize, s.HeaderSize, s.Size, s.SignatureHeader} {
		err := binary.Write(b, binary.LittleEndian, v)
		if err != nil {
			log.Fatalf("Couldn't write signature list: %s", err)
		}
	}
	for _, l := range s.Signatures {
		WriteSignatureData(b, l)
	}
}

func WriteSignatureLists(b *bytes.Buffer, siglist []*SignatureList) {
	for _, l := range siglist {
		WriteSignatureList(b, *l)
	}
}

func ReadSignatureList(f *bytes.Reader) *SignatureList {
	s := SignatureList{}
	for _, i := range []interface{}{&s.SignatureType, &s.ListSize, &s.HeaderSize, &s.Size} {
		if err := binary.Read(f, binary.LittleEndian, i); err != nil {
			log.Fatalf("Couldn't read signature list: %s", err)
		}
	}

	var sigData []SignatureData

	// The list size minus the size of the SignatureList struct
	// lets us figure out how much signature data we should read
	totalSize := s.ListSize - SizeofSignatureList

	// fmt.Println(s.SignatureType.Format())
	sig := ValidEFISignatureSchemes[s.SignatureType]
	// Anonymous function because I really can't figure out a better name for it
	parseList := func(data []SignatureData, size uint32) []SignatureData {
		for {
			if totalSize == 0 {
				break
			}
			data = append(data, *ReadSignatureData(f, size))
			totalSize -= s.Size
		}
		return data
	}
	switch sig {
	case "X509":
		if s.HeaderSize != 0 {
			log.Fatalf("Unexpected HeaderSize for x509 cert. Should be 0!")
		}
		sigData = parseList(sigData, s.Size)
	case "SHA256":
		if s.HeaderSize != 0 {
			log.Fatalf("Unexpected HeaderSize for SHA256. Should be 0!")
		}
		if s.Size != 48 {
			log.Fatalf("Unexpected signature size for SHA256. Should be 16+32!")
		}
		sigData = parseList(sigData, s.Size)
	default:
		log.Fatalf("Not implemented signature list certificate: %s", sig)
	}
	s.Signatures = sigData
	return &s
}

// Reads several signature lists from a bytes Reader
// TODO: Needs a better name
func ReadSignatureLists(f *bytes.Reader) []*SignatureList {
	siglist := []*SignatureList{}
	for {
		if f.Len() == 0 {
			break
		}
		siglist = append(siglist, ReadSignatureList(f))
	}
	return siglist
}
