package util

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
)

func ReadKey(path string) *rsa.PrivateKey {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		panic("failed to parsePEM block containing the public key!")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded private key: " + err.Error())
	}
	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		return priv
	default:
		panic("unknown type of public key")
	}
}

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
