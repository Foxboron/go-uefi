package pecoff

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"fmt"

	"github.com/foxboron/go-uefi/efi/pkcs7"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/pkg/errors"
)

func CreateSignature(ctx *PECOFFSigningContext, Cert *x509.Certificate, Key *rsa.PrivateKey) []byte {

	sigCtx := &pkcs7.SigningContext{
		Cert:     Cert,
		Key:      Key,
		SigData:  ctx.SigData.Bytes(),
		Indirect: true,
	}
	return pkcs7.SignData(sigCtx)
}

func AppendToBinary(PEFile *PECOFFSigningContext, sig []byte) []byte {

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
	buf := PEFile.PEFile[PEFile.DD4Start:PEFile.DD4End]
	if err := binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &datadir); err != nil {
		panic("There isn't any DataDirectory struct in the offset. There should be!")
	}

	if datadir.VirtualAddress != 0 && datadir.Size != 0 {
		datadir = pe.DataDirectory{
			VirtualAddress: datadir.VirtualAddress,
			Size:           datadir.Size + info.Length,
		}
	} else {
		// Only signature we found
		datadir = pe.DataDirectory{
			VirtualAddress: uint32(PEFile.OriginalSize),
			Size:           info.Length,
		}
	}

	// This pads the signature since Authenticode demands each of them are
	// aligned up to 8 bytes
	padBytes, PadSize := PaddingBytes(int(info.Length), 8)
	datadir.Size += uint32(PadSize)
	certBuf.Write(padBytes)

	// Create the struct and overwrite the datadirectory
	datadirBuf := new(bytes.Buffer)
	if err := binary.Write(datadirBuf, binary.LittleEndian, &datadir); err != nil {
		panic("Can't create DataDir with context")
	}
	copy(PEFile.PEFile[PEFile.DD4Start:], datadirBuf.Bytes())

	// Append the certificate at the end of the file
	// TODO: Should we optimize this?
	pefile := append(PEFile.PEFile, certBuf.Bytes()...)
	return pefile
}

// TODO: Need 32 bit support
func GetSignatureDataDirectory(pefile []byte) (*pe.DataDirectory, error) {
	buf := bytes.NewReader(pefile)
	f, err := pe.NewFile(buf)
	if err != nil {
		return nil, errors.Wrapf(err, "could parse PE file")
	}
	return &f.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[4], nil
}

// This fetches the attached signature data
func GetSignatureBytesFromFile(pefile []byte) ([]byte, error) {
	datadir, err := GetSignatureDataDirectory(pefile)
	if err != nil {
		return nil, errors.Wrapf(err, "could not get datadirectory")
	}
	addr := datadir.VirtualAddress
	certSize := datadir.Size
	return pefile[addr : addr+certSize], nil
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
