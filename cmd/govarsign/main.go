package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/util"
)

func main() {
	key := flag.String("key", "", "Key")
	cert := flag.String("cert", "", "Certificate")
	variable := flag.String("var", "", "variable")
	flag.Parse()
	args := flag.Args()
	if len(os.Args) == 1 {
		fmt.Println("govarsign: -key <key> -cert <cert> -var <variable> [input] [output]")
	}
	if len(os.Args) == 2 {
		fmt.Println("Missing input and output file")
		os.Exit(1)
	}
	b, err := ioutil.ReadFile(args[0])
	if err != nil {
		log.Fatal(err)
	}
	keyFile, err := util.ReadKeyFromFile(*key)
	if err != nil {
		log.Fatal(err)
	}
	certFile, err := util.ReadCertFromFile(*cert)
	if err != nil {
		log.Fatal(err)
	}
	buf, err := efi.SignEFIVariable(keyFile, certFile, *variable, b)
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile(args[1], buf, 0644)
	if err != nil {
		log.Fatal(err)
	}
}
