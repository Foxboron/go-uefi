package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
)

var (
	sigdata = signature.SignatureData{
		Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}},
		Data:  []uint8{}}
	certFile *x509.Certificate
	keyFile  *rsa.PrivateKey
)

func main() {
	var err error
	key := flag.String("key", "", "Key")
	cert := flag.String("cert", "", "Certificate")
	flag.Parse()
	keyFile, err = util.ReadKeyFromFile(*key)
	if err != nil {
		log.Fatal(err)
	}
	certFile, err = util.ReadCertFromFile(*cert)
	if err != nil {
		log.Fatal(err)
	}
	args := flag.Args()

	peFile, err := ioutil.ReadFile(args[1])
	if err != nil {
		log.Fatal(err)
	}
	// ctx := pecoff.PECOFFChecksum(peFile)
	// bufChecksum := sha256.Sum256(ctx.SigData.Bytes())
	bufChecksum := sha256.Sum256(peFile)
	sigdata.Data = bufChecksum[:]
	db, err := efi.Getdb()
	if err != nil {
		log.Fatal(err)
	}

	switch args[0] {
	case "show":
		fmt.Printf("%x", bufChecksum[:])
	case "append":
		err = db.AppendSignature(signature.CERT_SHA256_GUID, &sigdata)
	case "remove":
		err = db.RemoveSignature(signature.CERT_SHA256_GUID, &sigdata)
	}
	if err != nil {
		log.Fatal(err)
	}
	buf := new(bytes.Buffer)
	signature.WriteSignatureDatabase(buf, *db)
	bufSomething, err := efi.SignEFIVariable(keyFile, certFile, "db", buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	if err := efi.WriteEFIVariable("db", bufSomething); err != nil {
		log.Fatal(err)
	}
}
