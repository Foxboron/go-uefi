package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"

	"github.com/foxboron/go-uefi/efi/pecoff"
	"github.com/foxboron/go-uefi/efi/pkcs7"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	UEFIHandle = tpmutil.Handle(0x81010005)

	TemplateRSA = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

func NewKey(tpm io.ReadWriteCloser, handler tpmutil.Handle) (crypto.PublicKey, error) {
	cachedPub, _, _, err := tpm2.ReadPublic(tpm, handler)
	if err == nil {
		key, err := cachedPub.Key()
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	return nil, nil
}

func TPMToX509(tpmCert io.ReadWriteCloser, handle tpmutil.Handle) (*client.Key, *x509.Certificate, error) {
	key, err := client.NewCachedKey(tpmCert, tpm2.HandleEndorsement, templateSSA(), UEFIHandle)
	if err != nil {
		log.Fatal(err)
	}
	c := x509.Certificate{
		SerialNumber:       new(big.Int).SetInt64(1),
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		Subject: pkix.Name{
			Country:    []string{"TPM Signature"},
			CommonName: "TPM Signature",
		},
	}
	signer, err := key.GetSigner()
	if err != nil {
		return nil, nil, err
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &c, &c, key.PublicKey(), signer)
	if err != nil {
		return nil, nil, err
	}
	os.WriteFile("tpm.cert", derBytes, 0644)
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func templateSSA() tpm2.Public {
	template := client.AKTemplateRSA()
	template.Attributes &= ^tpm2.FlagRestricted
	template.RSAParameters.Sign.Hash = tpm2.AlgSHA256
	return template
}

func createTPMKey(tpm io.ReadWriteCloser) {
	_, _, err := TPMToX509(tpm, UEFIHandle)
	if err != nil {
		log.Fatal(err)
	}
}

func signTPM(tpm io.ReadWriteCloser, filename string) {
	Key, Cert, err := TPMToX509(tpm, UEFIHandle)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := Key.GetSigner()
	if err != nil {
		log.Fatal(err)
	}
	peFile, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	ctx := pecoff.PECOFFChecksum(peFile)
	sig, err := pecoff.CreateSignature(ctx, Cert, signer)
	if err != nil {
		log.Fatal(err)
	}
	b, err := pecoff.AppendToBinary(ctx, sig)
	if err != nil {
		log.Fatal(err)
	}
	if err = ioutil.WriteFile("tpm.signed", b, 0644); err != nil {
		log.Fatal(err)
	}
}

func verifyTPM(tpm io.ReadWriteCloser, filename string) {
	_, Cert, err := TPMToX509(tpm, UEFIHandle)
	if err != nil {
		log.Fatal(err)
	}
	peFile, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	sigs, err := pecoff.GetSignatures(peFile)
	if err != nil {
		log.Fatal(err)
	}
	if len(sigs) == 0 {
		fmt.Println("No signatures")
		os.Exit(1)
	}
	for _, signature := range sigs {
		if ok, _ := pkcs7.VerifySignature(Cert, signature.Certificate); ok {
			goto valid
		}
	}
	fmt.Println("Invalid")
	os.Exit(1)
valid:
	fmt.Println("Valid signature!")
}

func main() {
	if len(os.Args) <= 1 {
		os.Exit(1)
	}
	tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		log.Fatal(err)
	}

	switch os.Args[1] {
	case "create":
		createTPMKey(tpm)
	case "sign":
		signTPM(tpm, os.Args[2])
	case "verify":
		verifyTPM(tpm, os.Args[2])
	}
}
