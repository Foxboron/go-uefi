package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/foxboron/goefi/efi"
	"github.com/foxboron/goefi/efi/attributes"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("gowritevar [var] [efi variable]")
		os.Exit(1)
	}
	f := os.Args[2]
	attrs := efi.ValidAttributes[os.Args[1]]
	b, _ := ioutil.ReadFile(f)
	if err := attributes.WriteEfivars(os.Args[1], attrs, b); err != nil {
		log.Fatal(err)
	}
}
