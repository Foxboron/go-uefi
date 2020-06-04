package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/foxboron/goefi/efi/pecoff"
	"github.com/foxboron/goefi/efi/pkcs7"
	"github.com/foxboron/goefi/efi/signature"
	"github.com/foxboron/goefi/efi/util"
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
	x509Cert := util.ReadCert(*cert)
	b := pecoff.GetSignatures(peFile)
	reader := bytes.NewReader(b)
	var sigs []*signature.WINCertificate
	for {
		sig := signature.ReadWinCertificate(reader)
		sigs = append(sigs, &sig)
		if reader.Len() < signature.SizeofWINCertificate {
			break
		}
	}
	for _, signature := range sigs {
		if !pkcs7.VerifySignature(x509Cert, signature.Certificate) {
			fmt.Println("Invalid signature!")
			os.Exit(1)
		}
	}
	fmt.Println("Valid signature!")
}
