package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/foxboron/go-uefi/efi/pecoff"
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

	peFile, err := ioutil.ReadFile(args[0])
	if err != nil {
		log.Fatal(err)
	}

	ctx := pecoff.PECOFFChecksum(peFile)
	Cert, err := util.ReadCertFromFile(*cert)
	if err != nil {
		log.Fatal(err)
	}
	Key, err := util.ReadKeyFromFile(*key)
	if err != nil {
		log.Fatal(err)
	}

	sig, err := pecoff.CreateSignature(ctx, Cert, Key)
	if err != nil {
		log.Fatal(err)
	}

	b, err := pecoff.AppendToBinary(ctx, sig)
	if err != nil {
		log.Fatal(err)
	}
	if err = ioutil.WriteFile(args[1], b, 0644); err != nil {
		log.Fatal(err)
	}
}
