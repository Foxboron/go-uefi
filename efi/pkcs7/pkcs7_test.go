package pkcs7

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"testing"
)

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

func TestParseCertificate(t *testing.T) {
	cert, key := InitCert()

	ctx := &SigningContext{
		Cert:      cert,
		Key:       key,
		KeySigner: key,
		SigData:   []byte{0x00, 0x01},
		Indirect:  true,
	}

	buf, err := SignData(ctx)
	if err != nil {
		t.Fail()
	}
	ok, err := VerifySignature(ctx, buf)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if !ok {
		t.Fatalf("failed signature verification")
	}
}
