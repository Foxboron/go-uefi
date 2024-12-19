package authenticode

import (
	"bytes"
	"cmp"
	"crypto"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"slices"

	"github.com/pkg/errors"

	"github.com/foxboron/go-uefi/efi/signature"
)

var (
	// No singatures where found in the binary.
	ErrNoSignatures = errors.New("binary has no signatures")

	// No valid signatures where found in the binary.
	ErrNoValidSignatures = errors.New("binary has no valid signatures")
)

// PECOFFBinary represents a parsed PE/COFF binary.
type PECOFFBinary struct {
	// DataDirectory for the Certificate table
	Datadir pe.DataDirectory
	// Reader with the hashable bytes
	HashContent  *bytes.Buffer
	length       int
	padding      []byte
	optDataDir   *bytes.Reader
	certTable    *bytes.Buffer
	firstSection *io.SectionReader
	lastSection  *io.SectionReader
}

// Parse a PECOFF Binary.
// This will read the binary and collect all the bytes we are hashing.
func Parse(r io.ReaderAt) (*PECOFFBinary, error) {
	// 1. Load the image header into memory.
	// Done in io.ReaderAt

	// Instead of passing filesize as a parameter we'll keep track of the bytes we
	// are reading here
	var fileSize int

	// 2. Initialize a hash algorithm context
	hashBuffer, err := makeBuffer(r)
	if err != nil {
		return nil, fmt.Errorf("failed creating hash buffer: %v", err)
	}

	readSection := func(r io.ReaderAt, dst io.Writer, off, n int64) error {
		src := io.NewSectionReader(r, off, n-off)
		if _, err := io.Copy(dst, src); err != nil {
			return err
		}
		return nil
	}

	// Wraps r and hashBuffer with section readers
	readBytes := func(off, n int64) error {
		return readSection(r, hashBuffer, off, n)
	}

	f, err := pe.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("failed reading PE file: %v", err)
	}
	defer f.Close()

	// This finds the start of the file until the start of the PE file
	// We can ignore any sanity checking debug/pe did that for us
	// We are simply peaking back into the buffer with whatever it told us
	var dosheader [96]byte
	if _, err := r.ReadAt(dosheader[0:], 0); err != nil {
		return nil, err
	}
	offset := int64(binary.LittleEndian.Uint32(dosheader[0x3c:])) + int64(binary.Size(f.FileHeader)) + 4

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

	// 3. Hash the image header from its base to immediately before the start of
	// the checksum address, as specified in Optional Header Windows-Specific
	// Fields.
	if err := readBytes(0, cksumStart); err != nil {
		return nil, err
	}

	// 4. Skip over the checksum, which is a 4-byte field.
	cksumEnd := cksumStart + 4

	// 5. Hash everything from the end of the checksum field to immediately before
	// the start of the Certificate Table entry, as specified in Optional Header
	// Data Directories.
	if err := readBytes(cksumEnd, dd4start); err != nil {
		return nil, err
	}

	firstSection := io.NewSectionReader(r, 0, dd4start)

	// 6. Get the Attribute Certificate Table address and size from the
	// Certificate Table entry.
	dd4end := dd4start + 8

	// We save this so we can replace the optDataDir at a later point
	var datadir bytes.Buffer
	readSection(r, &datadir, dd4start, dd4end)

	optDataDir := bytes.NewReader(datadir.Bytes())
	// filecontent.Add(optDataDir)

	// 7. Exclude the Certificate Table entry from the calculation and hash everything
	// from the end of the Certificate Table entry to the end of image header,
	// including Section Table (headers). The Certificate Table entry is 8 bytes long,
	// as specified in Optional Header Data Directories.
	if err := readBytes(dd4end, SizeOfHeaders); err != nil {
		return nil, err
	}

	// 8. Create a counter called SUM_OF_BYTES_HASHED, which is not part of the
	// signature. Set this counter to the SizeOfHeaders field, as specified in Optional
	// Header Windows-Specific Field.
	sumOfBytesHashed := SizeOfHeaders

	// 9. Build a temporary table of pointers to all of the section headers in the
	// image. The NumberOfSections field of COFF File Header indicates how big the
	// table should be.
	sections := f.Sections

	// 10. Using the PointerToRawData field (offset 20) in the referenced SectionHeader
	// structure as a key, arrange the table's elements in ascending order. In other
	// words, sort the section headers in ascending order according to the disk-file
	// offset of the sections.
	slices.SortFunc(sections, func(a, b *pe.Section) int { return cmp.Compare(a.Offset, b.Offset) })

	for _, sec := range sections {
		// Do not include any section headers in the table whose SizeOfRawData field is zero.
		if sec.Size == 0 {
			continue
		}

		// 11. Walk through the sorted table, load the corresponding section into
		// memory, and hash the entire section. Use the SizeOfRawData field in the
		// SectionHeader structure to determine the amount of data to hash.
		if _, err = hashBuffer.ReadFrom(sec.Open()); err != nil {
			return nil, fmt.Errorf("can't parse section data from binary: %v", err)
		}

		// 12. Add the section’s SizeOfRawData value to SUM_OF_BYTES_HASHED.
		sumOfBytesHashed += int64(sec.Size)
	}
	// 13. Repeat steps 11 and 12 for all of the sections in the sorted table.

	// 14. Create a value called FILE_SIZE, which is not part of the signature. Set
	// this value to the image’s file size, acquired from the underlying file system.
	// If FILE_SIZE is greater than SUM_OF_BYTES_HASHED, the file contains extra data
	// that must be added to the hash. This data begins at the SUM_OF_BYTES_HASHED file
	// offset, and its length is: (FILE_SIZE) – ((Size of AttributeCertificateTable) +
	// SUM_OF_BYTES_HASHED)
	// This is a hacky one.
	// We don't have the FILE_SIZE because we take an io.ReaderAt into the
	// function.
	// We could pass the file size as a paramter, but I didn't think that was
	// interesting.

	// sumOfBytesHashed should containt the absolue filesize value we have been
	// reading so far.
	fileSize += int(sumOfBytesHashed)

	// Make a bytes.Buffer with all the remaining bytes
	var rest bytes.Buffer
	if err := readSection(r, &rest, sumOfBytesHashed, 1<<63-1); err != nil {
		return nil, err
	}

	// rest.Len() should be the complete remaining bytes.
	fileSize += rest.Len()

	// length minus the certificate directory size
	// this should give us a buffer with everything up ontil the certificates we can hash.
	binaryRest := rest.Len() - int(ddEntry.Size)

	// Truncate the buffer with buffer length.
	rest.Truncate(binaryRest)

	// Copy the remaining bytes into the hashbuffer
	if _, err := io.Copy(hashBuffer, &rest); err != nil {
		return nil, err
	}

	// Add an offset reader to read all the remaining bytes
	lastSection := io.NewSectionReader(r, dd4end, (sumOfBytesHashed+int64(binaryRest))-dd4end)

	// If FILE_SIZE is not a multiple of 8 bytes, the data added to the hash must be appended with zero
	// padding of length (8 – (FILE_SIZE % 8)) bytes.
	paddingBytes, n := PaddingBytes(fileSize, 8)
	hashBuffer.Write(paddingBytes)

	fileSize += n

	// Read and discard the entire filecontent.
	if err := readSection(r, io.Discard, 0, 1<<63-1); err != nil {
		return nil, err
	}

	var certTable bytes.Buffer
	sr := io.NewSectionReader(r, int64(ddEntry.VirtualAddress), int64(ddEntry.Size))
	if _, err := io.Copy(&certTable, sr); err != nil {
		return nil, err
	}

	return &PECOFFBinary{
		length:       fileSize,
		padding:      paddingBytes,
		certTable:    &certTable,
		HashContent:  hashBuffer,
		Datadir:      ddEntry,
		firstSection: firstSection,
		optDataDir:   optDataDir,
		lastSection:  lastSection,
	}, nil
}

// Append an signature to the file.
func (p *PECOFFBinary) AppendSignature(sig []byte) error {
	// var w bytes.Buffer
	info := signature.WINCertificate{
		Length:      uint32(signature.SizeofWINCertificate + len(sig)),
		Revision:    0x0200,
		CertType:    signature.WIN_CERT_TYPE_PKCS_SIGNED_DATA,
		Certificate: sig,
	}

	signature.WriteWinCertificate(p.certTable, &info)

	// If we can find a data directory 4, it means there are certificates on this immage.
	// We modify the size if we can find it, else we create it from scratch
	if p.Datadir.VirtualAddress != 0 && p.Datadir.Size != 0 {
		p.Datadir.Size += info.Length
	} else {
		// No singatures are present
		// This is just a wrong Virtual Address. I have no clue if it actually matters
		p.Datadir.VirtualAddress = uint32(p.length)
		p.Datadir.Size = info.Length
	}

	// This pads the signature since Authenticode demands each of them are
	// aligned up to 8 bytes
	padBytes, PadSize := PaddingBytes(int(info.Length), 8)
	p.Datadir.Size += uint32(PadSize)
	p.certTable.Write(padBytes)

	// Write to the 8 byte LimitedReader we have inserted into our MultiWriter
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, &p.Datadir); err != nil {
		return fmt.Errorf("failed appending signature: %v", err)
	}

	p.optDataDir = bytes.NewReader(b.Bytes())

	return nil
}

// Sign the PE/COFF binary and return the signature.
// .Bytes() will return the binary with the signature appended.
func (p *PECOFFBinary) Sign(key crypto.Signer, cert *x509.Certificate) ([]byte, error) {
	sig, err := SignAuthenticode(key, cert, p.HashContent.Bytes(), crypto.SHA256)
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

// Bytes returns the binary with any appended signatures
func (p *PECOFFBinary) Bytes() []byte {
	b := bytes.NewBuffer(make([]byte, 0, p.firstSection.Size()+
		p.optDataDir.Size()+
		p.lastSection.Size()+
		int64(len(p.padding))+
		int64(p.certTable.Len()),
	))

	b.ReadFrom(p.Open())

	return b.Bytes()
}

// Open returns an io.Reader containing the binary with any appended signatures
func (p *PECOFFBinary) Open() io.Reader {
	return io.MultiReader(
		io.NewSectionReader(p.firstSection, 0, p.firstSection.Size()),
		io.NewSectionReader(p.optDataDir, 0, p.optDataDir.Size()),
		io.NewSectionReader(p.lastSection, 0, p.lastSection.Size()),
		bytes.NewReader(p.padding),
		bytes.NewReader(p.certTable.Bytes()),
	)
}

// Hash makes a hash of the HashContent bytes.
func (p *PECOFFBinary) Hash(h crypto.Hash) []byte {
	hh := h.New()
	hh.Write(p.HashContent.Bytes())
	return hh.Sum(nil)
}

func (p *PECOFFBinary) signatureBytes() []byte {
	return p.certTable.Bytes()
}

// Signatures returns a slice of *signature.WINCertificate which contains the
// WINCert wrapped Authenticode signatures.
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

func makeBuffer(r io.ReaderAt) (*bytes.Buffer, error) {
	s, ok := r.(io.Seeker)
	if !ok {
		return bytes.NewBuffer(nil), nil
	}

	// Our reader is a seeker, we can seek to the end and get the size, and avoid
	// unnecessary allocations during the buffer grow.
	size, err := s.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}

	slc := make([]byte, 0, size)

	_, err = s.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	return bytes.NewBuffer(slc), nil
}
