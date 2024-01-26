package authenticode

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"sort"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/pkg/errors"
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
	HashContent *bytes.Buffer
	// Complete file content that has been read
	fileContent *readers
	length      int
	optDataDir  *bytes.Reader
	certTable   *bytes.Buffer
}

// Internal reader representation of the file we are dealing with
type readers []io.ReadSeeker

func (r *readers) Add(newreader io.ReadSeeker) {
	*r = append(*r, newreader)
}

func (r *readers) AddOffsetReader(newreader io.ReaderAt, off, n int64) {
	sr := io.NewSectionReader(newreader, off, n-off)
	r.Add(sr)
}

func (r readers) Multireader() io.Reader {
	var rs []io.Reader
	for _, rr := range r {
		rs = append(rs, (io.Reader)(rr))
	}
	return io.MultiReader(rs...)
}

func (r readers) Reset() {
	for _, rr := range r {
		rr.Seek(0, io.SeekStart)
	}
}

// Parse a PECOFF Binary.
// This will read the binary and collect all the bytes we are hashing.
func Parse(r io.ReaderAt) (*PECOFFBinary, error) {
	// This is an amazing hack.
	// Instead of doing surgey with NewOffsetWriter or a raw byteslice,
	// we record all the SectionReaders we have and insert our own by replacing byte slices.
	// we then join everything with a MultiReader to get the entire file content.
	var filecontent readers

	// 1. Load the image header into memory.
	// Done in io.ReaderAt

	// Instead of passing filesize as a parameter we'll keep track of the bytes we
	// are reading here
	var fileSize int

	// 2. Initialize a hash algorithm context
	hashBuffer := new(bytes.Buffer)

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

	filecontent.AddOffsetReader(r, 0, cksumStart)

	// 4. Skip over the checksum, which is a 4-byte field.
	cksumEnd := cksumStart + 4

	filecontent.AddOffsetReader(r, cksumStart, cksumEnd)

	// 5. Hash everything from the end of the checksum field to immediately before
	// the start of the Certificate Table entry, as specified in Optional Header
	// Data Directories.
	if err := readBytes(cksumEnd, dd4start); err != nil {
		return nil, err
	}

	filecontent.AddOffsetReader(r, cksumEnd, dd4start)

	// 6. Get the Attribute Certificate Table address and size from the
	// Certificate Table entry.
	dd4end := dd4start + 8

	// We save this so we can replace the optDataDir at a later point
	var datadir bytes.Buffer
	readSection(r, &datadir, dd4start, dd4end)

	optDataDir := bytes.NewReader(datadir.Bytes())
	filecontent.AddOffsetReader(optDataDir, 0, 8)

	// 7. Exclude the Certificate Table entry from the calculation and hash everything
	// from the end of the Certificate Table entry to the end of image header,
	// including Section Table (headers). The Certificate Table entry is 8 bytes long,
	// as specified in Optional Header Data Directories.
	if err := readBytes(dd4end, SizeOfHeaders); err != nil {
		return nil, err
	}

	filecontent.AddOffsetReader(r, dd4end, SizeOfHeaders)

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
	sort.Slice(sections, func(i, j int) bool { return sections[i].Offset < sections[j].Offset })

	for _, sec := range sections {
		// Do not include any section headers in the table whose SizeOfRawData field is zero.
		if sec.Size == 0 {
			continue
		}

		// 11. Walk through the sorted table, load the corresponding section into
		// memory, and hash the entire section. Use the SizeOfRawData field in the
		// SectionHeader structure to determine the amount of data to hash.
		buf, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("can't parse section data from binary: %v", err)
		}
		hashBuffer.Write(buf)

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

	filecontent.AddOffsetReader(r, SizeOfHeaders, sumOfBytesHashed)

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
	filecontent.AddOffsetReader(r, sumOfBytesHashed, int64(binaryRest))

	// If FILE_SIZE is not a multiple of 8 bytes, the data added to the hash must be appended with zero
	// padding of length (8 – (FILE_SIZE % 8)) bytes.
	paddingBytes, _ := PaddingBytes(fileSize, 8)
	hashBuffer.Write(paddingBytes)

	// Read the entire filecontent into memory.
	var fileContent bytes.Buffer
	if err := readSection(r, &fileContent, 0, 1<<63-1); err != nil {
		return nil, err
	}

	var certTable bytes.Buffer
	sr := io.NewSectionReader(r, int64(ddEntry.VirtualAddress), int64(ddEntry.Size))
	if _, err := io.Copy(&certTable, sr); err != nil {
		return nil, err
	}
	// filecontent.Add(&certTable)

	return &PECOFFBinary{
		fileContent: &filecontent,
		length:      fileSize,
		optDataDir:  optDataDir,
		certTable:   &certTable,
		HashContent: hashBuffer,
		Datadir:     ddEntry,
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

// Return the binary with any appended signatures
func (p *PECOFFBinary) Bytes() []byte {
	var b bytes.Buffer
	if _, err := io.Copy(&b, p.fileContent.Multireader()); err != nil {
		log.Fatalf("failed reading from Multireader: %v", err)
	}
	b.Write(p.certTable.Bytes())
	p.fileContent.Reset()
	return b.Bytes()
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
