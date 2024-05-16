package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/efivar"
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
	b, err := os.ReadFile(args[0])
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

	var wvar efivar.Efivar
	switch *variable {
	case "db":
		wvar = efivar.Db
	case "KEK":
		wvar = efivar.KEK
	case "PK":
		wvar = efivar.PK
	}

	siglist, err := signature.ReadSignatureDatabase(bytes.NewReader(b))
	if err != nil {
		log.Fatal(err)
	}

	_, sl, err := signature.SignEFIVariable(wvar, &siglist, keyFile, certFile)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(args[1], sl.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}

}
