// Package for helper function in the test suite
package asntest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path"
	"testing"
)

// Init a basic set of certs
func InitCert() (*x509.Certificate, *rsa.PrivateKey) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}
	c := x509.Certificate{
		SerialNumber:       serialNumber,
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject: pkix.Name{
			Country: []string{"TEST STRING"},
		},
	}

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}

	derBytes, _ := x509.CreateCertificate(rand.Reader, &c, &c, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(derBytes)
	return cert, priv
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
