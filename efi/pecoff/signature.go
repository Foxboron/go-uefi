package pecoff

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"log"

	"github.com/foxboron/goefi/efi/pkcs7"
	"github.com/foxboron/goefi/efi/signature"
)

// TODO: This probably doesn't work when there are other signatures present
func SignPECOFF(ctx *PECOFFSigningContext) []byte {
	hasCert := false

	var datadir pe.DataDirectory
	buf := ctx.PEFile[ctx.DD4Start:ctx.DD4End]
	if err := binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &datadir); err != nil {
		panic("There isn't any DataDirectory struct in the offset. There should be!")
	}
	if datadir.VirtualAddress != 0 && datadir.Size != 0 {
		hasCert = true
	}

	// Need to pack the data before hashing
	// Should be moved outside of the signing code
	certTablePad := (ctx.OriginalSize + 7) / 8 * 8
	certTablePad = certTablePad - ctx.OriginalSize
	ctx.PEFile = append(ctx.PEFile, make([]byte, certTablePad)...)
	ctx.SigData.Write(make([]byte, certTablePad))

	sigCtx := &pkcs7.SigningContext{
		Cert:     ctx.Cert,
		Key:      ctx.Key,
		SigData:  ctx.SigData.Bytes(),
		Indirect: true,
	}

	detachedSignature := pkcs7.SignData(sigCtx)

	padded := (len(detachedSignature) + 7) / 8 * 8
	info := signature.WINCertificate{
		Length:      uint32(8 + padded),
		Revision:    0x0200,
		CertType:    signature.WIN_CERT_TYPE_PKCS_SIGNED_DATA,
		Certificate: detachedSignature,
	}
	var certBuf bytes.Buffer

	for _, v := range []interface{}{info.Length, info.Revision, info.CertType, info.Certificate} {
		binary.Write(&certBuf, binary.LittleEndian, v)
	}

	// This packs the certificate upwards
	certBuf.Write(make([]byte, padded-len(detachedSignature)))

	// If we can find a data directory 4, it means there are certificates on this immage.
	// We modify the size if we can find it, else we create it from scratch
	if !hasCert {
		datadir = pe.DataDirectory{
			VirtualAddress: uint32(ctx.OriginalSize + certTablePad),
			Size:           uint32(padded + 8),
		}
	} else {
		datadir = pe.DataDirectory{
			VirtualAddress: datadir.VirtualAddress,
			Size:           datadir.Size + uint32(padded+8),
		}
	}

	// Create the struct and overwrite the datadirectory
	datadirBuf := new(bytes.Buffer)
	if err := binary.Write(datadirBuf, binary.LittleEndian, &datadir); err != nil {
		panic("Can't create DataDir with context")
	}
	copy(ctx.PEFile[ctx.DD4Start:], datadirBuf.Bytes())

	// Append the certificate at the end of the file
	// TODO: Should we optimize this?
	pefile := append(ctx.PEFile, certBuf.Bytes()...)
	return pefile
}

func GetSignatures(peFile []byte) (*pe.DataDirectory, []byte) {
	buf := bytes.NewReader(peFile)
	f, err := pe.NewFile(buf)
	if err != nil {
		log.Fatal(err)
	}
	datadir := f.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[4]
	addr := datadir.VirtualAddress
	certSize := datadir.Size
	return &datadir, peFile[addr : addr+certSize]
}
