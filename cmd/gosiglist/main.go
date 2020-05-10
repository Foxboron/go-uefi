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
	if len(os.Args) == 1 {
		fmt.Println("gosiglist: -o <Owner GUID> [input] [output]")
	}
	if len(os.Args) != 3 {
		fmt.Println("Missing input and output file")
		os.Exit(1)
	}
	input := os.Args[1]
	output := os.Args[2]
	guid := util.StringToGUID(*owner)
	b, _ := ioutil.ReadFile(input)
	c := signature.NewSignatureList(b, *guid, signature.CERT_X509)
	buf := new(bytes.Buffer)
	signature.WriteSignatureList(buf, *c)
	err := ioutil.WriteFile(output, buf.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
}
