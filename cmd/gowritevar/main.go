package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/foxboron/goefi/efi"
	"github.com/foxboron/goefi/efi/attributes"
)

func main() {
	f := "KEK.auth"
	b, _ := ioutil.ReadFile(f)
	fil, err := os.OpenFile("/sys/firmware/efi/efivars/KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c", os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	buf := new(bytes.Buffer)
	attrs := efi.ValidAttributes["KEK"]
	attrs |= attributes.EFI_VARIABLE_APPEND_WRITE
	binary.Write(buf, binary.LittleEndian, attrs)
	n, err := fil.Write(append(buf.Bytes(), b...))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(n)
	if err := fil.Close(); err != nil {
		log.Fatal(err)
	}
}
