package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/foxboron/go-uefi/authenticode"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/pkcs7"
)

func main() {
	key := flag.String("key", "", "Key")
	cert := flag.String("cert", "", "Certificate")
	addcert := flag.String("addcert", "", "Additional intermediate certificates in a file")
	flag.Parse()
	args := flag.Args()
	if len(os.Args) == 1 {
		fmt.Println("gosign: -key <key> -cert <cert> [-addcert <addcertfile>] [input] [output]")
	}
	if len(args) < 2 {
		fmt.Println("Missing input and output file")
		os.Exit(1)
	}

	peFile, err := os.Open(args[0])
	if err != nil {
		log.Fatal(err)
	}

	Cert, err := util.ReadCertFromFile(*cert)
	if err != nil {
		log.Fatal(err)
	}
	Key, err := util.ReadKeyFromFile(*key)
	if err != nil {
		log.Fatal(err)
	}

	file, err := authenticode.Parse(peFile)
	if err != nil {
		log.Fatal(err)
	}

	// Check if additional certificates were provided
	if *addcert != "" {
		additionalCerts, err := util.ReadCertsFromFile(*addcert)
		if err != nil {
			log.Fatalf("Failed to read additional certificates: %v", err)
		}

		// Filter out the signing certificate if it's accidentally included
		var filteredCerts []*x509.Certificate
		for _, c := range additionalCerts {
			if !c.Equal(Cert) {
				filteredCerts = append(filteredCerts, c)
			}
		}

		if _, err = file.Sign(Key, Cert, pkcs7.WithAdditionalCerts(filteredCerts)); err != nil {
			log.Fatal(err)
		}
	} else {
		if _, err := file.Sign(Key, Cert); err != nil {
			log.Fatal(err)
		}
	}

	if err = os.WriteFile(args[1], file.Bytes(), 0644); err != nil {
		log.Fatal(err)
	}
}
