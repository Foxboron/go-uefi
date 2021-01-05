package device

import (
	"bytes"
	"io/ioutil"
	"log"
	"testing"

	"github.com/foxboron/go-uefi/efi/attributes"
)

func TestAbs(t *testing.T) {
	dir := "../../tests/data/boot"
	attributes.Efivars = dir
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		s, _ := attributes.ReadEfivars(file.Name()[:8])
		f := bytes.NewReader(s.Data)
		ParseEFILoadOption(f)
		ParseDevicePath(f)
	}
}
