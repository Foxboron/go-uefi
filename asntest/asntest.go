// Package for helper function in the test suite
package asntest

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"testing"
)

func CertToBytes(cert *x509.Certificate) []byte {
	certOut := new(bytes.Buffer)
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %v", err)
	}
	return certOut.Bytes()
}

func RSAToBytes(r *rsa.PrivateKey) []byte {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(r)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	keyOut := new(bytes.Buffer)
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		log.Fatalf("Failed to write data to key.pem: %v", err)
	}
	return keyOut.Bytes()
}

func Asn1Parse(t *testing.T, buf []byte) []byte {
	f := path.Join(t.TempDir(), "asn1.der")
	os.WriteFile(f, buf, 0644)
	out, err := exec.Command("openssl", "asn1parse", "-in", f, "-inform", "der", "-dump", "-i").Output()
	if err != nil {
		fmt.Println(string(out))
		log.Fatal(err)
	}
	return out
}

func DiffText(t *testing.T, a, b []byte) {
	aFile := path.Join(t.TempDir(), "a.der")
	bFile := path.Join(t.TempDir(), "b.der")
	os.WriteFile(aFile, a, 0644)
	os.WriteFile(bFile, b, 0644)
	out, _ := exec.Command("git", "diff", "--color=always", "--no-index", "--", aFile, bFile).Output()
	if len(out) > 0 {
		fmt.Println(string(a))
		fmt.Println(string(b))
		fmt.Println(string(out))
	}
}

func Asn1Compare(t *testing.T, a, b []byte) {
	a = Asn1Parse(t, a)
	b = Asn1Parse(t, b)
	DiffText(t, a, b)
}
