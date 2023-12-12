package authenticode

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/foxboron/go-uefi/asntest"
)

func mustHexdump(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("decodeHex: %s", err)
	}
	return b
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
			checksum, err := Checksum(b)
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
