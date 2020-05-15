package signature

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
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
		panic("failed to parsePEM block containg the public key!")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	return cert
}

func TestVerifySignature(t *testing.T) {
	//pathAuth := "../../tests/data/signatures/varsign/PK.auth"
	pathAuth := "../../empty.db.signed"

	b, _ := ioutil.ReadFile(pathAuth)
	f := bytes.NewReader(b)
	d := ReadEFIVariableAuthencation2(f)
	buf := new(bytes.Buffer)
	WriteEFIVariableAuthencation2(buf, *d)
	readBuf := make([]byte, f.Len())
	binary.Read(f, binary.LittleEndian, readBuf)
	buf.Write(readBuf)
	err := ioutil.WriteFile("../../test-suite.empty.db", buf.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
}
