package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/foxboron/goefi/efi/attributes"
	"github.com/foxboron/goefi/efi/pecoff"
	"github.com/foxboron/goefi/efi/pkcs7"
	"github.com/foxboron/goefi/efi/signature"
)

func ParseSignatureList(filename string) {
	s, _ := attributes.ReadEfivarsFile(filename)
	f := bytes.NewReader(s.Data)
	siglist := signature.ReadSignatureLists(f)
	for _, sig := range siglist {
		fmt.Printf("Signature Type: %s\n", signature.ValidEFISignatureSchemes[sig.SignatureType])
		fmt.Printf("Signature List List Size : %d\n", sig.ListSize)
		fmt.Printf("Signature List Header Size : %d\n", sig.HeaderSize)
		fmt.Printf("Signature List Size : %d\n", sig.Size)
		fmt.Printf("Signature List Signature Header: %x\n", sig.SignatureHeader)
		fmt.Printf("Signature List Signatures:\n")
		for _, sigEntry := range sig.Signatures {
			fmt.Printf("	Signature Owner: %s\n", sigEntry.Owner.Format())
			switch sig.SignatureType {
			case signature.CERT_X509_GUID:
				cert, _ := x509.ParseCertificate(sigEntry.Data)
				fmt.Printf("	Issuer: %s\n", cert.Issuer.String())
				fmt.Printf("	Serial Number: %d\n", cert.SerialNumber)
			}
		}
	}
}

func ParseEFIImage(filename string) {
	b, _ := ioutil.ReadFile(filename)
	datadir, sigbuf := pecoff.GetSignatures(b)
	reader := bytes.NewReader(sigbuf)
	fmt.Println("Data Directory Header:")
	fmt.Printf("	Virtual Address: 0x%x\n", datadir.VirtualAddress)
	fmt.Printf("	Size in bytes: %d\n", datadir.Size)
	if datadir.Size == 0 {
		fmt.Println("No signatures")
		os.Exit(1)
	}
	for {
		sig := signature.ReadWinCertificate(reader)
		fmt.Printf("Certificate Type: %s\n", signature.WINCertTypeString[sig.CertType])
		c := pkcs7.ParseSignature(sig.Certificate)
		for _, si := range c.Content.SignerInfos {
			var issuer pkix.RDNSequence
			asn1.Unmarshal(si.IssuerAndSerialNumber.IssuerName.FullBytes, &issuer)
			fmt.Printf("	Issuer Name: %s\n", issuer.String())
			fmt.Printf("	Serial Number: %s\n", si.IssuerAndSerialNumber.SerialNumber)
		}
		if reader.Len() < signature.SizeofWINCertificate {
			break
		}
	}
}

func main() {
	if len(os.Args) == 1 {
		log.Fatalln("Need type")
	}
	if len(os.Args) == 2 {
		log.Fatalln("Need filename")
	}
	efiType := os.Args[1]
	file := os.Args[2]

	switch efiType {
	case "KEK", "PK", "db":
		ParseSignatureList(file)
	case "signed-image":
		ParseEFIImage(file)
	}

}
