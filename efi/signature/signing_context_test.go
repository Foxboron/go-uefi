package signature

import (
	"bytes"
	"io/ioutil"
	"log"
	"testing"
)

// Doesn't do anything
func TestVerifySignature(t *testing.T) {
	pathAuth := "../../tests/data/signatures/varsign/PK.auth"
	b, _ := ioutil.ReadFile(pathAuth)
	f := bytes.NewReader(b)
	d, err := ReadEFIVariableAuthencation2(f)
	if err != nil {
		log.Fatal(err)
	}
	buf := new(bytes.Buffer)
	WriteEFIVariableAuthencation2(buf, *d)
}
