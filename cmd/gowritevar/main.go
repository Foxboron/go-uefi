package main

import (
	"fmt"
	"log"
	"os"

	"github.com/foxboron/go-uefi/efi"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("gowritevar [var] [efi variable]")
		os.Exit(1)
	}
	b, err := os.ReadFile(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	if err := efi.WriteEFIVariable(os.Args[1], b); err != nil {
		log.Fatal(err)
	}
}
