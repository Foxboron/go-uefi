package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"log"
	"os"

	"github.com/foxboron/go-uefi/authenticode"
	"github.com/foxboron/go-uefi/efi/attributes"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/pkcs7"
)

func FormatSignatureList(siglist []*signature.SignatureList) {
	fmt.Printf("\nNumber of Signatures in the Signature List: %d\n", len(siglist))
	for _, sig := range siglist {
		fmt.Printf("\nSignature Type: %s\n", signature.ValidEFISignatureSchemes[sig.SignatureType])
		fmt.Printf("Signature List List Size : %d\n", sig.ListSize)
		fmt.Printf("Signature List Header Size : %d\n", sig.HeaderSize)
		fmt.Printf("Signature List Size : %d\n", sig.Size)
		fmt.Printf("Signature List Signature Header: %x (usually empty)\n", sig.SignatureHeader)
		fmt.Printf("Signature List Number of Signatures: %d\n", len(sig.Signatures))
		fmt.Printf("Signature List Signatures:\n")
		for _, sigEntry := range sig.Signatures {
			fmt.Printf("	Signature Owner: %s\n", sigEntry.Owner.Format())
			switch sig.SignatureType {
			case signature.CERT_X509_GUID:
				cert, _ := x509.ParseCertificate(sigEntry.Data)
				fmt.Printf("		Issuer: %s\n", cert.Issuer.String())
				fmt.Printf("		Serial Number: %d\n", cert.SerialNumber)
			case signature.CERT_SHA256_GUID:
				fmt.Printf("		Type: %s\n", "SHA256")
				fmt.Printf("		Checksum: %x\n", sigEntry.Data)
			default:
				fmt.Println("Not implemented!")
				fmt.Println(sig.SignatureType.Format())
			}
		}
	}
}

func ParseKeyDb(filename string) {
	_, f, _ := attributes.ReadEfivarsFile(filename)
	siglist, err := signature.ReadSignatureDatabase(f)
	if err != nil {
		log.Fatal(err)
	}
	FormatSignatureList(siglist)
}

func ParseSignatureList(filename string) {
	b, _ := os.ReadFile(filename)
	f := bytes.NewReader(b)
	siglist, err := signature.ReadSignatureDatabase(f)
	if err != nil {
		log.Fatal(err)
	}
	FormatSignatureList(siglist)
}

func FormatEFIVariableAuth2(sig *signature.EFIVariableAuthentication2) {
	fmt.Println("EFI Authentication Variable")
	fmt.Printf("	EFI Signing Time: %s\n", sig.Time.Format())
	fmt.Println("	WINCertificate Info")
	fmt.Println("		Header:")
	fmt.Printf("			Length %d\n", sig.AuthInfo.Header.Length)
	fmt.Printf("			Revision: 0x%x (should be 0x200) \n", sig.AuthInfo.Header.Revision)
	fmt.Printf("			CertType: %s\n", signature.WINCertTypeString[sig.AuthInfo.Header.CertType])
	fmt.Printf("		Certificate Type: ")
	switch sig.AuthInfo.CertType {
	case signature.EFI_CERT_TYPE_RSA2048_SHA256_GUID:
		fmt.Println("RSA2048 SHA256")
	case signature.EFI_CERT_TYPE_PKCS7_GUID:
		fmt.Println("PKCS7")
	}
	// pkcs7.ParseSignature(sig.AuthInfo.CertData)
	// l, err := moz.Parse(sig.AuthInfo.CertData)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Printf("%+v", l)

	// err := ioutil.WriteFile("test.bin", sig.AuthInfo.CertData, 0644)
	// if err != nil {
	// 	log.Fatal(err)
	// }
}

func ParseEFIAuthVariable(filename string) {
	b, _ := os.ReadFile(filename)
	reader := bytes.NewReader(b)
	// Fetch the signature
	sig, err := signature.ReadEFIVariableAuthencation2(reader)
	if err != nil {
		log.Fatal(err)
	}
	FormatEFIVariableAuth2(sig)
	siglist, err := signature.ReadSignatureDatabase(reader)
	if err != nil {
		log.Fatal(err)
	}
	FormatSignatureList(siglist)
}

func ParseEFIImage(filename string) {
	b, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	binary, err := authenticode.Parse(bytes.NewReader(b))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Data Directory Header:")
	fmt.Printf("	Virtual Address: 0x%x\n", binary.Datadir.VirtualAddress)
	fmt.Printf("	Size in bytes: %d\n", binary.Datadir.Size)
	if binary.Datadir.Size == 0 {
		fmt.Println("No signatures")
	}

	signatures, err := binary.Signatures()
	if err != nil {
		log.Fatal(err)
	}
	for _, sig := range signatures {
		fmt.Printf("Certificate Type: %s\n", signature.WINCertTypeString[sig.CertType])
		c, err := pkcs7.ParsePKCS7(sig.Certificate)
		if err != nil {
			log.Fatal(err)
		}
		for range c.SignerInfo {
			// TODO: Implement issuer and serial number parsing
			continue
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
	case "KEK", "PK", "db", "dbx":
		ParseKeyDb(file)
	case "siglist":
		ParseSignatureList(file)
	case "signed":
		ParseEFIAuthVariable(file)
	case "signed-image":
		ParseEFIImage(file)
	}

}
