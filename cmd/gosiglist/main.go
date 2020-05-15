package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/foxboron/goefi/efi/signature"
	"github.com/foxboron/goefi/efi/util"
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
	b, err := ioutil.ReadFile(input)
	if err != nil {
		log.Fatal(err)
	}
	c := signature.NewSignatureList(b, *guid, signature.CERT_X509)
	buf := new(bytes.Buffer)
	signature.WriteSignatureList(buf, *c)
	err = ioutil.WriteFile(output, buf.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
}
