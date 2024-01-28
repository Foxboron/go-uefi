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
	key := flag.String("key", "", "Key")
	cert := flag.String("cert", "", "Certificate")
	flag.Parse()
	args := flag.Args()
	if len(os.Args) == 1 {
		fmt.Println("gosign: -key <key> -cert <cert> [input] [output]")
	}
	if len(os.Args) == 2 {
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
	file.Sign(Key, Cert)

	if err = os.WriteFile(args[1], file.Bytes(), 0644); err != nil {
		log.Fatal(err)
	}
}
