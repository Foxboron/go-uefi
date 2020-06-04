package signature

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"log"

	"github.com/foxboron/goefi/efi/attributes"
	"github.com/foxboron/goefi/efi/util"
	"github.com/foxboron/pkcs7"
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
	sd, err := pkcs7.NewSignedData(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	// Page 246

	// SignedData.digestAlgorithms shall contain the digest algorithm used when
	// preparing the signature. Only a digest algorithm of SHA-256 is accepted

	// SignerInfo.digestEncryptionAlgorithm shall be set to the algorithm used to
	// sign the data. Only a digest encryption algorithm of RSA with PKCS #1 v1.5
	// padding (RSASSA_PKCS1v1_5). is accepted.

	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	sd.SetEncryptionAlgorithm(pkcs7.OIDEncryptionAlgorithmRSA)

	if err := sd.AddSigner(ctx.Cert, ctx.Key, pkcs7.SignerInfoConfig{}); err != nil {
		log.Fatalf("Cannot add signer: %s", err)
	}
	sd.RemoveUnauthenticatedAttributes()
	sd.Detach()
	detachedSignature, err := sd.Finish()
	if err != nil {
		log.Fatal(err)
	}
	efva.AuthInfo.Header.Length += uint32(len(detachedSignature))
	efva.AuthInfo.CertData = detachedSignature
	return efva
}
