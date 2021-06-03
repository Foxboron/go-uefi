package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/foxboron/go-uefi/efi/pecoff"
	"github.com/foxboron/go-uefi/efi/pkcs7"
	"github.com/foxboron/go-uefi/efi/util"
)

//"github.com/sassoftware/relic/lib/authenticode"
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

	peFile, err := ioutil.ReadFile(args[0])
	if err != nil {
		log.Fatal(err)
	}
	x509Cert, err := util.ReadCertFromFile(*cert)
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
		if ok, _ := pkcs7.VerifySignature(x509Cert, signature.Certificate); !ok {
			fmt.Println("Invalid signature!")
			os.Exit(1)
		}
	}
	fmt.Println("Valid signature!")
}
