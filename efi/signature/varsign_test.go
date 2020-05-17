package signature

import (
	"bytes"
	"io/ioutil"
	"log"
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
		b, _ := ioutil.ReadFile(path)
		f := bytes.NewReader(b)
		ReadEFIVariableAuthencation2(f)
	}
}
