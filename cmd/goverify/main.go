package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/foxboron/go-uefi/authenticode"
	"github.com/foxboron/go-uefi/efi/util"
)

func main() {
	cert := flag.String("cert", "", "Certificate")
	flag.Parse()
	args := flag.Args()
	if len(os.Args) == 1 {
		fmt.Println("goverify: -cert <cert> [input")
	}
	if len(os.Args) == 1 {
		fmt.Println("Missing input and output file")
		os.Exit(1)
	}

	peFile, err := os.Open(args[0])
	if err != nil {
		log.Fatal(err)
	}
	x509Cert, err := util.ReadCertFromFile(*cert)
	if err != nil {
		log.Fatal(err)
	}

	binary, err := authenticode.Parse(peFile)
	if err != nil {
		log.Fatal(err)
	}

	ok, err := binary.Verify(x509Cert)
	if err != nil {
		log.Fatal(err)
	}

	if !ok {
		fmt.Println("Invalid signature")
		os.Exit(1)
	}
	fmt.Println("Valid signature")
}
