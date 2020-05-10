package signature

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func TestReadEFIVariableAuthentication2File(t *testing.T) {
	dir := "../../tests/data/signatures/varsign"
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		path := filepath.Join(dir, file.Name())
		file, _ := os.Open(path)
		b, _ := ioutil.ReadAll(file)
		f := bytes.NewReader(b)
		ReadEFIVariableAuthencation2(f)
	}
}
