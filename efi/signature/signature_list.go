package signature

import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"io"
	"log"
	"reflect"

	"github.com/foxboron/go-uefi/efi/util"
	"github.com/pkg/errors"
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
func GetSupportedSignatures(f io.Reader) ([]util.EFIGUID, error) {
	// This is a bit bad. But io.Reader is *probably nicer* but we need to know
	// the length in a better way.
	buf := new(bytes.Buffer)
	buf.ReadFrom(f)
	supportedSigs := make([]util.EFIGUID, buf.Len()/16)
	if err := binary.Read(buf, binary.LittleEndian, &supportedSigs); err != nil {
		return nil, errors.Wrapf(err, "could not parse EFIGUIDs from this reader")
	}
	return supportedSigs, nil
}

// Section 32.4.1 - Signature Database
// Page 1712
type SignatureData struct {
	Owner util.EFIGUID
	Data  []uint8
}

func ReadSignatureData(f io.Reader, size uint32) (*SignatureData, error) {
	s := SignatureData{}
	if err := binary.Read(f, binary.LittleEndian, &s.Owner); err != nil {
		return &SignatureData{}, errors.Wrapf(err, "could not read Signature Data")
	}
	data := make([]uint8, size-util.SizeofEFIGUID) // Subtract the size of Owner
	if err := binary.Read(f, binary.LittleEndian, &data); err != nil {
		return &SignatureData{}, errors.Wrapf(err, "Couldn't read Signature Data")
	}
	s.Data = data[:]
	return &s, nil
}

func WriteSignatureData(b io.Writer, s SignatureData) {
	for _, v := range []interface{}{s.Owner, s.Data} {
		err := binary.Write(b, binary.LittleEndian, v)
		if err != nil {
			log.Fatalf("Couldn't write signature data: %s", err)
		}
	}
}

func (sd *SignatureData) Bytes() []byte {
	buf := new(bytes.Buffer)
	WriteSignatureData(buf, *sd)
	return buf.Bytes()
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

// SignatureSize + sizeof(SignatureType) + sizeof(uint32)*3
const SizeofSignatureList uint32 = util.SizeofEFIGUID + 4 + 4 + 4

var ErrNotFoundSigData = errors.New("signature data not found")
var ErrSigDataExists = errors.New("signature data exists already")

func NewSignatureList(certtype util.EFIGUID) *SignatureList {
	return &SignatureList{
		SignatureType:   certtype,
		ListSize:        SizeofSignatureList,
		HeaderSize:      0,
		Size:            0,
		SignatureHeader: []uint8{},
		Signatures:      []SignatureData{},
	}
}

// Compare the signature lists header to see if they are the same type of list
// This is usefull if you wonder if you can merge the lists or not
func (sl *SignatureList) CmpHeader(siglist *SignatureList) bool {
	if !util.CmpEFIGUID(sl.SignatureType, siglist.SignatureType) {
		return false
	}
	if sl.Size != siglist.Size {
		return false
	}
	if !reflect.DeepEqual(sl.SignatureHeader, siglist.SignatureHeader) {
		return false
	}
	return true
}

// Check if signature exists in the signature list
// Return true if it does along with the index
func (sl *SignatureList) Exists(sigdata *SignatureData) (bool, int) {
	for index, sigs := range sl.Signatures {
		if !util.CmpEFIGUID(sigs.Owner, sigdata.Owner) {
			continue
		}
		if !bytes.Equal(sigs.Data, sigdata.Data) {
			continue
		}
		return true, index
	}
	return false, 0
}

func (sl *SignatureList) ExistsInList(siglist *SignatureList) bool {
	for _, item := range siglist.Signatures {
		if ok, _ := sl.Exists(&item); !ok {
			return false
		}
	}
	return true
}

func (sl *SignatureList) AppendBytes(owner util.EFIGUID, data []byte) error {
	if ok, _ := sl.Exists(&SignatureData{owner, data}); ok {
		return ErrSigDataExists
	}
	switch sl.SignatureType {
	case CERT_X509_GUID:
		// Check if the cert is PEM encoded
		// We need the DER encoded cert, but this makes it nicer
		// for us in the API
		if block, _ := pem.Decode(data); block != nil {
			data = block.Bytes
		}
	case CERT_SHA256_GUID:
		if len(data) != 32 {
			return errors.New("not a sha256 hash")
		}
	}
	sl.Signatures = append(sl.Signatures, SignatureData{Owner: owner, Data: data})
	sl.Size = uint32(len(data)) + util.SizeofEFIGUID
	sl.ListSize += sl.Size
	return nil
}

func (sl *SignatureList) AppendSignature(s SignatureData) error {
	return sl.AppendBytes(s.Owner, s.Data)
}

func (sl *SignatureList) RemoveBytes(owner util.EFIGUID, data []byte) error {
	ok, index := sl.Exists(&SignatureData{owner, data})
	if !ok {
		return ErrNotFoundSigData
	}
	if len(sl.Signatures) == 1 {
		*sl = *NewSignatureList(sl.SignatureType)
		return nil
	}
	sl.Signatures = append(sl.Signatures[:index], sl.Signatures[index+1:]...)
	sl.ListSize -= sl.Size
	return nil
}

func (sl *SignatureList) RemoveSignature(s SignatureData) error {
	return sl.RemoveBytes(s.Owner, s.Data)
}

func (sl *SignatureList) Bytes() []byte {
	buf := new(bytes.Buffer)
	WriteSignatureList(buf, *sl)
	return buf.Bytes()
}

// Writes a signature list
func WriteSignatureList(b io.Writer, s SignatureList) {
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

// Read an EFI_SIGNATURE_LIST from io.Reader. It will read until io.EOF.
// io.EOF should be somewhat expected if we are trying to read multiple
// lists as they should be either at the end of the file, or the entire file.
func ReadSignatureList(f io.Reader) (*SignatureList, error) {
	s := SignatureList{}
	for _, i := range []interface{}{&s.SignatureType, &s.ListSize, &s.HeaderSize, &s.Size} {
		err := binary.Read(f, binary.LittleEndian, i)
		if errors.Is(err, io.EOF) {
			return &SignatureList{}, err
		} else if err != nil {
			return &SignatureList{}, errors.Wrapf(err, "couldn't read signature list")
		}
	}

	var sigData []SignatureData
	var err error

	// The list size minus the size of the SignatureList struct
	// lets us figure out how much signature data we should read.
	totalSize := s.ListSize - SizeofSignatureList

	sig := ValidEFISignatureSchemes[s.SignatureType]
	// Anonymous function because I really can't figure out a better name for it
	parseList := func(data []SignatureData, size uint32) ([]SignatureData, error) {
		for {
			if totalSize == 0 {
				return data, nil
			}
			sigdata, err := ReadSignatureData(f, size)
			if err != nil {
				return nil, err
			}
			data = append(data, *sigdata)
			totalSize -= s.Size
		}
	}
	switch sig {
	case "X509":
		if s.HeaderSize != 0 {
			log.Fatalf("Unexpected HeaderSize for x509 cert. Should be 0!")
		}
		sigData, err = parseList(sigData, s.Size)
	case "SHA256":
		if s.HeaderSize != 0 {
			log.Fatalf("Unexpected HeaderSize for SHA256. Should be 0!")
		}
		if s.Size != 48 {
			log.Fatalf("Unexpected signature size for SHA256. Should be 16+32!")
		}
		sigData, err = parseList(sigData, s.Size)
	default:
		// if s.Size != 0 {
		// 	buf := make([]byte, s.Size)
		// 	if err := binary.Read(f, binary.LittleEndian, buf); err != nil {
		// 		return nil, errors.Wrap(err, "could not read default list")
		// 	}
		// }
		log.Fatalf("Not implemented signature list certificate: %s", sig)
	}
	if err != nil {
		return &SignatureList{}, err
	}
	s.Signatures = sigData
	return &s, nil
}
