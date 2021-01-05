package signature

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"log"

	"github.com/foxboron/go-uefi/efi/attributes"
	"github.com/foxboron/go-uefi/efi/pkcs7"
	"github.com/foxboron/go-uefi/efi/util"
)

// Handles the values we use for EFI Variable signatures
type EFIVariableSigningContext struct {
	Cert    *x509.Certificate
	Key     *rsa.PrivateKey
	Varname []byte
	Attr    attributes.Attributes
	Guid    util.EFIGUID
	Data    []byte
}

// Uses EFIVariableAuthentication2
// Section 8.2.2 - Using the EFI_VARIABLE_AUTHENTICATION_2 descriptor
func NewSignedEFIVariable(ctx *EFIVariableSigningContext) *EFIVariableAuthentication2 {
	// TODO: Move to internal pkcs7 library
	buf := new(bytes.Buffer)
	efva := NewEFIVariableAuthentication2()
	// The order is important
	// TODO: Expose the Time variable
	s := []byte{}
	for _, n := range ctx.Varname {
		s = append(s, n, 0x00)
	}
	writeOrder := []interface{}{
		s,
		ctx.Guid,
		ctx.Attr,
		efva.Time,
		ctx.Data,
	}
	for _, d := range writeOrder {
		if err := binary.Write(buf, binary.LittleEndian, d); err != nil {
			log.Fatal(err)
		}
	}

	sigCtx := &pkcs7.SigningContext{
		Cert:     ctx.Cert,
		Key:      ctx.Key,
		SigData:  buf.Bytes(),
		Indirect: false,
	}

	detachedSignature := pkcs7.SignData(sigCtx)

	efva.AuthInfo.Header.Length += uint32(len(detachedSignature))
	efva.AuthInfo.CertData = detachedSignature
	return efva
}
