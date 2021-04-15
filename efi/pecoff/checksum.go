package pecoff

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"log"
)

type PECOFFSigningContext struct {
	Cert         *x509.Certificate
	Key          *rsa.PrivateKey
	DD4Start     int64
	DD4End       int64
	OriginalSize int
	PEFile       []byte
	SigData      *bytes.Buffer
	Indirect     bool
}

func PECOFFChecksum(peFile []byte) *PECOFFSigningContext {

	buf := bytes.NewReader(peFile)
	f, err := pe.NewFile(buf)
	if err != nil {
		log.Fatal(err)
	}

	hashBuffer := new(bytes.Buffer)

	// This finds the start of the file until the start of the PE file
	// We can ignore any sanity checking debug/pe did that for us
	// We are simply peaking back into the buffer with whatever it told us
	offset := int64(binary.LittleEndian.Uint32(peFile[:96][0x3c:])) + int64(binary.Size(f.FileHeader)) + 4

	var SizeOfHeaders int64
	var dd4start int64
	switch optHeader := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dd4start = offset + 128
		SizeOfHeaders = int64(optHeader.SizeOfHeaders)
	case *pe.OptionalHeader64:
		dd4start = offset + 144
		SizeOfHeaders = int64(optHeader.SizeOfHeaders)
	}

	// Finds where the checksum start
	cksumStart := offset + 64

	// Finds where the checksum ends
	cksumEnd := cksumStart + 4
	hashBuffer.Write(peFile[:cksumStart])

	// We should read until Optional Data directory 4, which is where the
	// certificates are located
	dd4end := dd4start + 8
	hashBuffer.Write(peFile[cksumEnd:dd4start])

	// Read rests of the opt data, if there is anything
	endOfOptHeader := offset + int64(f.SizeOfOptionalHeader)
	hashBuffer.Write(peFile[dd4end:endOfOptHeader])
	// fmt.Printf("%x\n", peFile[dd4start:dd4end])

	// Read from the start of the section (which is at the end of the Optional Header),
	// until the entire header has been read
	hashBuffer.Write(peFile[endOfOptHeader:SizeOfHeaders])

	// var offset uint32
	var sectionSize uint32
	var sectionOffset uint32
	for _, sec := range f.Sections {
		buf, err := sec.Data()
		if err != nil {
			log.Fatal(err)
		}
		hashBuffer.Write(buf)
		// Less complicated... I think
		// Grab the largest offset
		// which should be the end of our file
		if sec.Offset >= sectionOffset {
			sectionOffset = sec.Offset
			sectionSize = sec.Size
		}
	}

	// We actually know the Offset from the sections
	// But I CBA to do the math again
	// lastSection := len(f.Sections) - 1
	// sectionEnd := f.Sections[lastSection].Offset + f.Sections[lastSection].Size
	sectionEnd := sectionOffset + sectionSize
	addr := f.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[4].VirtualAddress
	certSize := f.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[4].Size

	if certSize > 0 {
		hashBuffer.Write(peFile[sectionEnd:addr])
	} else {
		hashBuffer.Write(peFile[sectionEnd:])
	}

	// Tianocore demands that we pad to 8 bytes
	// They also need to be added to the checksum file
	paddingBytes, _ := PaddingBytes(len(peFile), 8)
	peFile = append(peFile, paddingBytes...)
	hashBuffer.Write(paddingBytes)

	return &PECOFFSigningContext{
		PEFile:       peFile,
		SigData:      hashBuffer,
		OriginalSize: len(peFile),
		DD4Start:     dd4start,
		DD4End:       dd4end,
	}
}
