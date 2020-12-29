package signature

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"testing"
)

func ReadCert(path string) *x509.Certificate {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		panic("failed to parsePEM block containing the public key!")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	return cert
}

// Doesn't do anything
func TestVerifySignature(t *testing.T) {
	pathAuth := "../../tests/data/signatures/varsign/PK.auth"
	b, _ := ioutil.ReadFile(pathAuth)
	f := bytes.NewReader(b)
	d := ReadEFIVariableAuthencation2(f)
	buf := new(bytes.Buffer)
	WriteEFIVariableAuthencation2(buf, *d)
}
