package pecoff

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"fmt"

	"github.com/foxboron/go-uefi/efi/pkcs7"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/pkg/errors"
)

func CreateSignature(ctx *PECOFFSigningContext, Cert *x509.Certificate, Key crypto.Signer) ([]byte, error) {
	// Tianocore demands that we pad to 8 bytes
	// They also need to be added to the checksum file
	// We move this out of the checksum function since this padding is
	// only applied to the checksums used in the signature.
	paddingBytes, _ := PaddingBytes(len(ctx.PEFile), 8)
	ctx.PEFile = append(ctx.PEFile, paddingBytes...)
	ctx.SigData.Write(paddingBytes)

	sigCtx := &pkcs7.SigningContext{
		Cert:      Cert,
		KeySigner: Key,
		SigData:   ctx.SigData.Bytes(),
		Indirect:  true,
	}

	sd, err := pkcs7.SignData(sigCtx)
	if err != nil {
		return nil, err
	}
	return sd, nil
}

func AppendToBinary(PEFile *PECOFFSigningContext, sig []byte) ([]byte, error) {

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
		return nil, fmt.Errorf("there isn't any DataDirectory struct in the offset")
	}
	if datadir.VirtualAddress != 0 && datadir.Size != 0 {
		datadir = pe.DataDirectory{
			VirtualAddress: datadir.VirtualAddress,
			Size:           datadir.Size + info.Length,
		}
	} else {
		// Only signature we found
		datadir = pe.DataDirectory{
			VirtualAddress: uint32(len(PEFile.PEFile)),
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
		return nil, err
	}
	copy(PEFile.PEFile[PEFile.DD4Start:], datadirBuf.Bytes())

	// Append the certificate at the end of the file
	// TODO: Should we optimize this?
	pefile := append(PEFile.PEFile, certBuf.Bytes()...)
	return pefile, nil
}

func GetSignatureDataDirectory(pefile []byte) (pe.DataDirectory, error) {
	buf := bytes.NewReader(pefile)
	f, err := pe.NewFile(buf)
	if err != nil {
		return pe.DataDirectory{}, errors.Wrapf(err, "couldn't parse PE file")
	}
	defer f.Close()
	if oh64, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		return oh64.DataDirectory[4], nil
	}
	return f.OptionalHeader.(*pe.OptionalHeader32).DataDirectory[4], nil
}

// This fetches the attached signature data
func GetSignatureBytesFromFile(pefile []byte) ([]byte, error) {
	datadir, err := GetSignatureDataDirectory(pefile)
	if err != nil {
		return nil, errors.Wrapf(err, "could not get datadirectory")
	}
	addr := datadir.VirtualAddress
	certSize := datadir.Size
	if int(addr+certSize) > len(pefile) {
		// Most likely a corrupt binary
		return nil, fmt.Errorf("certificate size exceed the binary file")
	}
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
