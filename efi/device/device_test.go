package device

import (
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/foxboron/go-uefi/efi/attributes"
)

func TestAbs(t *testing.T) {
	dir := "../../tests/data/boot"
	attributes.Efivars = dir
	files, err := os.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		filepath := filepath.Join(dir, file.Name())
		_, f, err := attributes.ReadEfivarsFile(filepath)
		if err != nil {
			t.Fatal(err)
		}
		ParseEFILoadOption(f)
		ParseDevicePath(f)
	}
}
