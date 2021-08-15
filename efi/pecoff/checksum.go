package pecoff

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"log"
	"sort"
)

type PECOFFSigningContext struct {
	Cert     *x509.Certificate
	Key      *rsa.PrivateKey
	DD4Start int64
	DD4End   int64
	PEFile   []byte
	SigData  *bytes.Buffer
	Indirect bool
}

func PECOFFChecksum(peFile []byte) *PECOFFSigningContext {
	buf := bytes.NewReader(peFile)
	f, err := pe.NewFile(buf)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	hashBuffer := new(bytes.Buffer)

	// This finds the start of the file until the start of the PE file
	// We can ignore any sanity checking debug/pe did that for us
	// We are simply peaking back into the buffer with whatever it told us
	offset := int64(binary.LittleEndian.Uint32(peFile[:96][0x3c:])) + int64(binary.Size(f.FileHeader)) + 4

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
	hashBuffer.Write(peFile[:cksumStart])

	// We should read until Optional Data directory 4, which is where the
	// certificates are located
	dd4end := dd4start + 8
	hashBuffer.Write(peFile[cksumEnd:dd4start])

	// Read rests of the opt data, if there is anything
	endOfOptHeader := offset + int64(f.SizeOfOptionalHeader)
	hashBuffer.Write(peFile[dd4end:endOfOptHeader])

	// Read from the start of the section (which is at the end of the Optional Header),
	// until the entire header has been read
	hashBuffer.Write(peFile[endOfOptHeader:SizeOfHeaders])

	sections := f.Sections
	sort.Slice(sections, func(i, j int) bool { return sections[i].Offset < sections[j].Offset })

	sumOfBytes := SizeOfHeaders
	for _, sec := range sections {
		if sec.Size == 0 {
			continue
		}
		buf, err := sec.Data()
		if err != nil {
			log.Fatal(err)
		}
		hashBuffer.Write(buf)
		sumOfBytes += int64(sec.Size)
	}

	fileSize := int64(len(peFile))
	if fileSize > sumOfBytes {
		length := fileSize - sumOfBytes - int64(ddEntry.Size)
		hashBuffer.Write(peFile[sumOfBytes : sumOfBytes+length])
	}
	// We actually know the Offset from the sections
	// But I CBA to do the math again
	// lastSection := len(f.Sections) - 1
	// sectionEnd := f.Sections[lastSection].Offset + f.Sections[lastSection].Size

	return &PECOFFSigningContext{
		PEFile:   peFile,
		SigData:  hashBuffer,
		DD4Start: dd4start,
		DD4End:   dd4end,
	}
}
