package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
)

func main() {
	owner := flag.String("o", "", "GUID of the owner")
	flag.Parse()
	args := flag.Args()
	if len(args) == 1 {
		fmt.Println("gosiglist: -o <Owner GUID> [input] [output]")
	}
	if len(args) != 2 {
		fmt.Println("Missing input and output file")
		os.Exit(1)
	}
	input := args[0]
	output := args[1]
	guid := util.StringToGUID(*owner)
	b, err := os.ReadFile(input)
	if err != nil {
		log.Fatal(err)
	}
	c := signature.NewSignatureList(signature.CERT_X509_GUID)
	c.AppendBytes(*guid, b)
	buf := new(bytes.Buffer)
	signature.WriteSignatureList(buf, *c)
	err = os.WriteFile(output, buf.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
}
