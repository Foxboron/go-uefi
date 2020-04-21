package main

import (
	"io/ioutil"
	"log"
)

var EFIPath = "/sys/firmware/efi/efivars"

func main() {
	files, err := ioutil.ReadDir(EFIPath)
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
	}
}
