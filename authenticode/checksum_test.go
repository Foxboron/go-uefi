package authenticode

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/foxboron/go-uefi/asntest"
	"github.com/foxboron/go-uefi/efi/util"
)

func mustHexdump(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("decodeHex: %s", err)
	}
	return b
}

func mustOpen(s string) []byte {
	b, err := os.ReadFile(s)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func mustCertificate(s string) *x509.Certificate {
	b := mustOpen(s)
	block, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	return cert
}

func mustSigner(s string) crypto.Signer {
	b := mustOpen(s)
	k, err := util.ReadKey(b)
	if err != nil {
		log.Fatal(err)
	}
	return k
}

func TestSignVerify(t *testing.T) {
	cases := []struct {
		f              string
		checksum       []byte
		paddedchecksum []byte
	}{
		{
			f:              "../tests/data/binary/test.pecoff",
			checksum:       mustHexdump("9f2b505ce20bc20c2ce7f7a33cb93ca97d1465735ce6821a6fc8e8c7b1e0e60a"),
			paddedchecksum: mustHexdump("e7d74d2bc1287c17bf056e259ad7d2ca557e848b252509ae9956df0b14f69702"),
		},
		{
			f:              "../tests/data/binary/HelloWorld.efi",
			checksum:       mustHexdump("d2ae1f36ec9b40b55f60920a3f58ec902ebdc7c323e443412c751cdb3c42d3f3"),
			paddedchecksum: mustHexdump("765600a03f44d9f954376dd5f4e5b5e86b2ca1a3d6308a005f95922b0ebe7c94"),
		},
		{
			f:              "../tests/data/binary/HelloWorld.efi.signed",
			checksum:       mustHexdump("765600a03f44d9f954376dd5f4e5b5e86b2ca1a3d6308a005f95922b0ebe7c94"),
			paddedchecksum: mustHexdump("765600a03f44d9f954376dd5f4e5b5e86b2ca1a3d6308a005f95922b0ebe7c94"),
		},
		{
			f:              "../tests/data/binary/linuxx64.efi.stub",
			checksum:       mustHexdump("b9d3bcb414848ce11814ccb9fd98d95511e95fcc117c24e1517c9867761f251e"),
			paddedchecksum: mustHexdump("cc09c6b98fc5bf619ce09388399c35c21a510855f5fd308de653a8cf868e01cc"),
		},
	}

	cert, key := asntest.InitCert()

	for n, c := range cases {

		t.Run(fmt.Sprintf("case %d", n), func(t *testing.T) {
			b, err := os.ReadFile(c.f)
			if err != nil {
				log.Fatal(err)
			}
			checksum, err := Parse(bytes.NewReader(b))
			if err != nil {
				t.Fatalf("failed checksumming file: %v", err)
			}

			_, err = checksum.Sign(key, cert)
			if err != nil {
				t.Fatalf("failed signing binary: %v", err)
			}

			ok, err := checksum.Verify(cert)
			if err != nil {
				t.Fatalf("failed verify binary: %v", err)
			}

			if !ok {
				t.Fatalf("failed verify binary, not ok")
			}
		})
	}

}

func TestSbsignSignature(t *testing.T) {
	cases := []struct {
		f         []byte
		checksum  []byte
		cert      *x509.Certificate
		err       any
		ok        bool
		size      int
		fchecksum []byte
	}{
		{
			f:         mustOpen("testdata/test.pecoff"),
			checksum:  mustHexdump("e7d74d2bc1287c17bf056e259ad7d2ca557e848b252509ae9956df0b14f69702"),
			cert:      mustCertificate("testdata/db.pem"),
			err:       ErrNoSignatures,
			ok:        false,
			size:      3825,
			fchecksum: mustHexdump("c821d06f18e84ecd33d9a53954d366d76b5c595f5819a5076009106601fc8c31"),
		},
		{
			f:         mustOpen("testdata/test.pecoff.signed"),
			checksum:  mustHexdump("e7d74d2bc1287c17bf056e259ad7d2ca557e848b252509ae9956df0b14f69702"),
			err:       nil,
			cert:      mustCertificate("testdata/db.pem"),
			ok:        true,
			size:      6064,
			fchecksum: mustHexdump("1f9eee26e7e041b286bc42e220c2398594a6a2b25863155a7d88fd4e98ef5192"),
		},
	}

	for n, c := range cases {
		t.Run(fmt.Sprintf("case %d", n), func(t *testing.T) {
			checksum, err := Parse(bytes.NewReader(c.f))
			if err != nil {
				t.Fatalf("failed checksumming file: %v", err)
			}

			hashedbytes := checksum.Hash(crypto.SHA256)
			if !bytes.Equal(c.checksum, hashedbytes) {
				t.Fatalf("checksums didn't match. expected %x, got %x", c.checksum, hashedbytes)
			}

			if len(checksum.Bytes()) != c.size {
				t.Fatalf("incorrect size. expected %v, got %v", c.size, len(checksum.Bytes()))
			}

			h := crypto.SHA256.New()
			h.Write(checksum.Bytes())

			if !bytes.Equal(h.Sum(nil), c.fchecksum) {
				t.Fatalf("incorrect checksum.")
			}

			ok, err := checksum.Verify(c.cert)
			if !errors.As(err, &c.err) && (err != nil && c.err != nil) {
				t.Fatalf("failed verify function. expected %v, got %v", c.err, err)
			}

			if ok != c.ok {
				t.Fatalf("failed verify binary. expected %v, got %v", c.ok, ok)
			}
		})
	}
}

func TestSignVerifyWrite(t *testing.T) {
	cases := []struct {
		f         []byte
		checksum  []byte
		cert      *x509.Certificate
		key       crypto.Signer
		err       any
		ok        bool
		size      int
		fchecksum []byte
	}{
		{
			f:         mustOpen("testdata/test.pecoff"),
			checksum:  mustHexdump("e7d74d2bc1287c17bf056e259ad7d2ca557e848b252509ae9956df0b14f69702"),
			cert:      mustCertificate("testdata/db.pem"),
			key:       mustSigner("testdata/db.key"),
			err:       ErrNoSignatures,
			ok:        true,
			size:      3825,
			fchecksum: mustHexdump("c821d06f18e84ecd33d9a53954d366d76b5c595f5819a5076009106601fc8c31"),
		},
	}

	for n, c := range cases {
		t.Run(fmt.Sprintf("case %d", n), func(t *testing.T) {
			checksum, err := Parse(bytes.NewReader(c.f))
			if err != nil {
				t.Fatalf("failed checksumming file: %v", err)
			}

			_, err = checksum.Sign(c.key, c.cert)
			if err != nil {
				t.Fatalf("failed signing binary: %v", err)
			}

			ok, err := checksum.Verify(c.cert)
			if !errors.As(err, &c.err) && (err != nil && c.err != nil) {
				t.Fatalf("failed verify function. expected %v, got %v", c.err, err)
			}

			if ok != c.ok {
				t.Fatalf("failed verify binary. expected %v, got %v", c.ok, ok)
			}

			// Debugging
			// os.WriteFile(path.Join(dir, "test.signed"), checksum.Bytes(), 0644)
			// bb := mustOpen(path.Join(dir, "test.signed"))

			binary, err := Parse(bytes.NewReader(checksum.Bytes()))
			if err != nil {
				t.Fatalf("failed parsing binary the second time: %v", err)
			}

			ok, err = binary.Verify(c.cert)

			if !errors.As(err, &c.err) && (err != nil && c.err != nil) {
				t.Fatalf("failed second verify function. expected %v, got %v", c.err, err)
			}

			if ok != c.ok {
				t.Fatalf("failed second verify binary. expected %v, got %v", c.ok, ok)
			}
		})
	}
}

func TestWriteAndRead(t *testing.T) {
	f := mustOpen("testdata/test.pecoff.signed")

	cert := mustCertificate("testdata/db.pem")

	binary, _ := Parse(bytes.NewReader(f))

	data := binary.Bytes()

	// os.WriteFile(path.Join(d, "reconstructed.pecoff"), data, 0o644)

	coff, err := Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed parsing out written binary: %v", err)
	}

	h := crypto.SHA256.New()
	h.Write(coff.Bytes())

	ok, err := coff.Verify(cert)
	if err != nil {
		t.Fatalf("failed verify: %v", err)
	}

	if !ok {
		t.Fatalf("should be true")
	}
}
