package main

import (
	"bytes"
	"flag"
	"log"
	"os"
	"time"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
)

var sigdata = []signature.SignatureData{
	signature.SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x81, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
	signature.SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x82, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
	signature.SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x83, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
}

func main() {
	key := flag.String("key", "", "Key")
	cert := flag.String("cert", "", "Certificate")
	flag.Parse()

	sl := signature.NewSignatureList(signature.CERT_SHA256_GUID)
	for _, sig := range sigdata {
		sl.AppendBytes(sig.Owner, sig.Data)
	}

	buf := new(bytes.Buffer)
	signature.WriteSignatureList(buf, *sl)
	keyFile, err := util.ReadKeyFromFile(*key)
	if err != nil {
		log.Fatal(err)
	}
	certFile, err := util.ReadCertFromFile(*cert)
	if err != nil {
		log.Fatal(err)
	}

	signedBuf, err := efi.SignEFIVariable(keyFile, certFile, "dbx", buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	if err := efi.WriteEFIVariable("dbx", signedBuf); err != nil {
		log.Fatal(err)
	}

	time.Sleep(2 * time.Second)

	bufSomething, err := efi.SignEFIVariable(keyFile, certFile, "dbx", []byte{})
	if err != nil {
		log.Fatal(err)
	}
	if err := efi.WriteEFIVariable("dbx", bufSomething); err != nil {
		log.Fatal(err)
	}

	os.Exit(1)
	// fmt.Println("lol2")
	// signedBuf := efi.SignEFIVariable(util.ReadKey(*key), util.ReadCert(*cert), "dbx", buf.Bytes())
	// if err := efi.WriteEFIVariable("dbx", signedBuf); err != nil {
	// 	log.Fatal(err)
	// }

	// err := ioutil.WriteFile("dbx-siglist.bin", signedBuf, 0644)
	// if err != nil {
	// 	log.Fatal(err)
	// }

}
