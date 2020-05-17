package signature

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"testing"
)

func TestReadEFIVariableAuthentication2File(t *testing.T) {
	dir := "../../tests/data/signatures/varsign"
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}
	for _, _ = range files {
		// path := filepath.Join(dir, file.Name())
		path := "../../KEK.der.siglist.auth"
		b, _ := ioutil.ReadFile(path)
		f := bytes.NewReader(b)
		d := ReadEFIVariableAuthencation2(f)
		fmt.Printf("%+v\n", d.Time)
		break
	}
}
