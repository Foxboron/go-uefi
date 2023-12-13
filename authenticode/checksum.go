package authenticode

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/pkg/errors"
)

var (
	ErrNoSignatures      = errors.New("binary has no signatures")
	ErrNoValidSignatures = errors.New("binary has no valid signatures")
)

// Notes:
// This library should be using the pkcs7 librar

type datadirectorySignature struct {
	Datadir pe.DataDirectory
	Start   int64
	End     int64
}

type PECOFFBinary struct {
	DataDirectory datadirectorySignature
	fileContent   []byte
	HashContent   *bytes.Buffer
}

func Checksum(b []byte) (*PECOFFBinary, error) {
	buf := bytes.NewReader(b)
	f, err := pe.NewFile(buf)
	if err != nil {
		return nil, fmt.Errorf("failed reading PE file: %v", err)
	}
	defer f.Close()

	hashBuffer := new(bytes.Buffer)

	// This finds the start of the file until the start of the PE file
	// We can ignore any sanity checking debug/pe did that for us
	// We are simply peaking back into the buffer with whatever it told us
	offset := int64(binary.LittleEndian.Uint32(b[:96][0x3c:])) + int64(binary.Size(f.FileHeader)) + 4

	var SizeOfHeaders int64
	var dd4start int64
	var ddEntry pe.DataDirectory
	switch optHeader := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dd4start = offset + 128
		SizeOfHeaders = int64(optHeader.SizeOfHeaders)
		ddEntry = optHeader.DataDirectory[4]
	case *pe.OptionalHeader64:
		dd4start = offset + 144
		SizeOfHeaders = int64(optHeader.SizeOfHeaders)
		ddEntry = optHeader.DataDirectory[4]
	}

	// Finds where the checksum start
	cksumStart := offset + 64

	// Finds where the checksum ends
	cksumEnd := cksumStart + 4
	hashBuffer.Write(b[:cksumStart])

	// We should read until Optional Data directory 4, which is where the
	// certificates are located
	dd4end := dd4start + 8
	hashBuffer.Write(b[cksumEnd:dd4start])

	// Read rests of the opt data, if there is anything
	endOfOptHeader := offset + int64(f.SizeOfOptionalHeader)
	hashBuffer.Write(b[dd4end:endOfOptHeader])

	// Read from the start of the section (which is at the end of the Optional Header),
	// until the entire header has been read
	hashBuffer.Write(b[endOfOptHeader:SizeOfHeaders])

	sections := f.Sections
	sort.Slice(sections, func(i, j int) bool { return sections[i].Offset < sections[j].Offset })

	sumOfBytes := SizeOfHeaders
	for _, sec := range sections {
		if sec.Size == 0 {
			continue
		}
		buf, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("can't parse section data from binary: %v", err)
		}
		hashBuffer.Write(buf)
		sumOfBytes += int64(sec.Size)
	}

	fileSize := int64(len(b))
	if fileSize > sumOfBytes {
		length := fileSize - sumOfBytes - int64(ddEntry.Size)
		hashBuffer.Write(b[sumOfBytes : sumOfBytes+length])
	}
	// We actually know the Offset from the sections
	// But I CBA to do the math again
	// lastSection := len(f.Sections) - 1
	// sectionEnd := f.Sections[lastSection].Offset + f.Sections[lastSection].Size

	return &PECOFFBinary{
		fileContent: b,
		HashContent: hashBuffer,
		DataDirectory: datadirectorySignature{
			Start:   dd4start,
			End:     dd4end,
			Datadir: ddEntry,
		},
	}, nil
}

// Append an signature to the file
func (p *PECOFFBinary) AppendSignature(sig []byte) error {
	info := signature.WINCertificate{
		Length:      uint32(signature.SizeofWINCertificate + len(sig)),
		Revision:    0x0200,
		CertType:    signature.WIN_CERT_TYPE_PKCS_SIGNED_DATA,
		Certificate: sig,
	}

	var certBuf bytes.Buffer
	for _, v := range []interface{}{info.Length, info.Revision, info.CertType, info.Certificate} {
		binary.Write(&certBuf, binary.LittleEndian, v)
	}

	// If we can find a data directory 4, it means there are certificates on this immage.
	// We modify the size if we can find it, else we create it from scratch
	var datadir pe.DataDirectory
	buf := p.fileContent[p.DataDirectory.Start:p.DataDirectory.End]
	if err := binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &datadir); err != nil {
		return fmt.Errorf("there isn't any DataDirectory struct in the offset")
	}
	if p.DataDirectory.Datadir.VirtualAddress != 0 && p.DataDirectory.Datadir.Size != 0 {
		p.DataDirectory.Datadir.Size += info.Length
		p.DataDirectory.End += int64(info.Length)
	} else {
		// No singatures are present
		// This is just a wrong Virtual Address. I have no clue if it actually matters
		p.DataDirectory.Datadir.VirtualAddress = uint32(len(p.fileContent))
		p.DataDirectory.Datadir.Size = info.Length
	}

	// This pads the signature since Authenticode demands each of them are
	// aligned up to 8 bytes
	padBytes, PadSize := PaddingBytes(int(info.Length), 8)
	datadir.Size += uint32(PadSize)
	certBuf.Write(padBytes)

	// Create the struct and overwrite the datadirectory
	datadirBuf := new(bytes.Buffer)
	if err := binary.Write(datadirBuf, binary.LittleEndian, &datadir); err != nil {
		return fmt.Errorf("failed appending signature: %v", err)
	}
	copy(p.fileContent[p.DataDirectory.Start:], datadirBuf.Bytes())

	// Append the certificate at the end of the file
	// TODO: Should we optimize this?
	p.fileContent = append(p.fileContent, certBuf.Bytes()...)

	return nil
}

// Sign the PE/COFF binary and return the signature.
// .Bytes() will return the binary with the signature appended.
func (p *PECOFFBinary) Sign(key crypto.Signer, cert *x509.Certificate) ([]byte, error) {

	// Authenticode demands that stuff is aligned towards an 8 byte boundary.
	// It is unclear *when* this should be done, are unsigned binaries assumed to be padded?
	// Just padd it right before signing.
	paddingBytes, _ := PaddingBytes(len(p.fileContent), 8)
	p.fileContent = append(p.fileContent, paddingBytes...)
	p.HashContent.Write(paddingBytes)

	// TODO: Should this be a detail of SignAuthenticode?
	b := sha256.Sum256(p.HashContent.Bytes())

	sig, err := SignAuthenticode(key, cert, b[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed signing binary: %v", err)
	}
	if err := p.AppendSignature(sig); err != nil {
		return nil, fmt.Errorf("failed appending signatures: %v", err)
	}
	return sig, nil
}

// Verify signature
func (p *PECOFFBinary) Verify(cert *x509.Certificate) (bool, error) {
	sigs, err := p.Signatures()
	if err != nil {
		return false, fmt.Errorf("failed fetching certificates from binary: %v", err)
	}
	if len(sigs) == 0 {
		return false, ErrNoSignatures
	}
	for _, sig := range sigs {
		authcode, err := ParseAuthenticode(sig.Certificate)
		if err != nil {
			return false, fmt.Errorf("failed parsing pkcs7 signature from binary: %v", err)
		}
		ok, err := authcode.Verify(cert, p.HashContent.Bytes())
		if err != nil {
			return false, err
		}
		if !ok {
			continue
		}
		return true, nil
	}
	return false, ErrNoValidSignatures
}

// Return the binary with any appended signatures
func (p *PECOFFBinary) Bytes() []byte {
	return p.fileContent
}

func (p *PECOFFBinary) signatureBytes() []byte {
	addr := p.DataDirectory.Datadir.VirtualAddress
	certSize := p.DataDirectory.Datadir.Size
	if int(addr+certSize) > len(p.fileContent) {
		// Most likely a corrupt binary
		panic("malformed file")
	}
	return p.fileContent[addr : addr+certSize]
}

// Return WINCert
func (p *PECOFFBinary) Signatures() ([]*signature.WINCertificate, error) {
	var signatures []*signature.WINCertificate

	reader := bytes.NewReader(p.signatureBytes())
	for reader.Len() > signature.SizeofWINCertificate {
		sig, err := signature.ReadWinCertificate(reader)
		if err != nil {
			return []*signature.WINCertificate{}, errors.Wrap(err, "couldn't parse signature")
		}
		signatures = append(signatures, &sig)

		// All wCerts are padded up to 8 bytes
		// this figures out the padding and removes the bytes
		// so we don't parse them.
		_, size := PaddingBytes(int(sig.Length), 8)
		reader.Read(make([]byte, size))
	}
	return signatures, nil
}

func PaddingBytes(srcLen, blockSize int) ([]byte, int) {
	fullyPadded := (srcLen + blockSize - 1) &^ (blockSize - 1)
	padLen := fullyPadded - srcLen
	return make([]byte, padLen), padLen
}

func Padding(src []byte, blockSize int) []byte {
	padBytes, _ := PaddingBytes(len(src), blockSize)
	return append(src, padBytes...)
}
