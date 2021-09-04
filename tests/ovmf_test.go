// +build integration

package tests

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/foxboron/go-uefi/efi/pecoff"
	"github.com/foxboron/go-uefi/efi/pkcs7"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/tests/utils"
)

func TestOVMF(t *testing.T) {
	cert := util.ReadCert("./ovmf/keys/db/db.pem")
	key := util.ReadKey("./ovmf/keys/db/db.key")
	dir, _ := os.MkdirTemp("", "go-uefi-test")
	defer os.RemoveAll(dir) // clean up

	var testFiles = []struct {
		Name   string
		Bytes  []byte
		Expect string
	}{
		{
			Name:   "Unsigned.efi",
			Bytes:  pecoff.BinaryTest,
			Expect: "Access Denied",
		},
		{
			Name:   "SignedOnce.efi",
			Expect: "Ran",
		},
		{
			Name:   "SignedTwice.efi",
			Expect: "Ran",
		},
	}

	// I need to learn slices.........
	// TODO: Figure out how we should improve it.
	// But it works.
	newFile1 := make([]byte, len(testFiles[0].Bytes))
	copy(newFile1, testFiles[0].Bytes)
	ctx := pecoff.PECOFFChecksum(newFile1)
	sig := pecoff.CreateSignature(ctx, cert, key)
	testFiles[1].Bytes = pecoff.AppendToBinary(ctx, sig)

	newFile2 := make([]byte, len(testFiles[0].Bytes))
	copy(newFile2, testFiles[0].Bytes)
	ctx = pecoff.PECOFFChecksum(newFile2)
	sig = pecoff.CreateSignature(ctx, cert, key)
	testFiles[2].Bytes = pecoff.AppendToBinary(ctx, sig)

	ctx = pecoff.PECOFFChecksum(testFiles[2].Bytes)
	sig = pecoff.CreateSignature(ctx, cert, key)
	testFiles[2].Bytes = pecoff.AppendToBinary(ctx, sig)

	// Write unsigned file
	for _, file := range testFiles {
		f := filepath.Join(dir, file.Name)
		if err := os.WriteFile(f, file.Bytes, 0644); err != nil {
			log.Fatal(err)
		}
	}

	// TODO: This should be it's own thing
	for _, file := range testFiles {
		sigs, err := pecoff.GetSignatures(file.Bytes)
		if err != nil {
			t.Error(err)
		}
		if len(sigs) == 0 {
			continue
		}
		for _, signature := range sigs {
			ok, err := pkcs7.VerifySignature(cert, signature.Certificate)
			if !ok {
				t.Error("Couldn't validate certificate")
			}
			if err != nil {
				t.Error(err)
			}
		}
	}

	ovmf := utils.StartOVMF(utils.TestConfig{Shared: dir})
	defer ovmf.Kill()

	for _, file := range testFiles {
		cmd := fmt.Sprintf("fs0:%s\r\n", file.Name)
		ovmf.ConsoleWrite(cmd)
		// Ran - We did actually run the binary -> We have signed it
		// Access Denied -> We didn't sign it correctly
		re, _ := regexp.Compile(`(Ran|Access Denied)`)
		ret, _ := ovmf.ConsoleExpectRE(re)
		if ret[0] != file.Expect {
			t.Fatalf("Failed to run %s", file.Name)
		}
	}
}
