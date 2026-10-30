package efivarfs_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/foxboron/go-uefi/efi/attr"
	"github.com/foxboron/go-uefi/efi/attributes"
	"github.com/foxboron/go-uefi/efi/efitest"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/efivar"
	"github.com/foxboron/go-uefi/efivarfs"
	"github.com/foxboron/go-uefi/internal/certtest"

	. "github.com/foxboron/go-uefi/efivarfs/testfs"
)

var (
	sigdata = []signature.SignatureData{
		signature.SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x81, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
		signature.SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x82, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
		signature.SignatureData{Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}, Data: []uint8{0x83, 0xb4, 0xd9, 0x69, 0x31, 0xbf, 0xd, 0x2, 0xfd, 0x91, 0xa6, 0x1e, 0x19, 0xd1, 0x4f, 0x1d, 0xa4, 0x52, 0xe6, 0x6d, 0xb2, 0x40, 0x8c, 0xa8, 0x60, 0x4d, 0x41, 0x1f, 0x92, 0x65, 0x9f, 0xa}},
	}
)

func TestGetSecureBootEfivar(t *testing.T) {
	efivarfs := NewTestFS().
		With(efitest.SetUpModeOff()).
		Open()
	ok, err := efivarfs.GetSetupMode()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if ok != true {
		t.Fatalf("wrong")
	}
}

func TestWriteSignatureDatabaseEfivar(t *testing.T) {
	efivarfs := NewTestFS().Open()

	// Write some test data
	var wsb signature.SignatureDatabase
	for _, sig := range sigdata {
		wsb.AppendSignature(signature.CERT_SHA256_GUID, &sig)
	}

	if err := efivarfs.WriteVar(efivar.Db, &wsb); err != nil {
		t.Fatalf("encountered error: %v", err)
	}

	var rsb signature.SignatureDatabase
	if err := efivarfs.GetVar(efivar.Db, &rsb); err != nil {
		t.Fatalf("encountered error: %v", err)
	}

	if !reflect.DeepEqual(wsb[0].Signatures, rsb[0].Signatures) {
		t.Fatalf("Not equal")
	}
}

func TestWriteSignatureDatabaseEfivarAuthedUpdate(t *testing.T) {
	efivarfs := NewTestFS().Open()

	cert, priv := certtest.MkCert(t)

	// Write some test data
	var wsb signature.SignatureDatabase
	for _, sig := range sigdata {
		wsb.AppendSignature(signature.CERT_SHA256_GUID, &sig)
	}

	err := efivarfs.WriteSignedUpdate(efivar.Db, &wsb, priv, cert)
	if err != nil {
		t.Fatal(err)
	}

	rsb, err := efivarfs.Getdb()
	if err != nil {
		t.Fatalf("encountered error: %v", err)
	}

	if !reflect.DeepEqual(wsb[0].Signatures, (*rsb)[0].Signatures) {
		t.Fatalf("Not equal")
	}
}

func TestGetBootOrder(t *testing.T) {
	efivarfs := NewTestFS().
		With(
			fstest.MapFS{
				"/sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c": {Data: []byte{
					// 0001,2001,2002,2003,0000
					0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x20, 0x02, 0x20, 0x03, 0x20, 0x00, 0x00,
				}},
			},
		).
		Open()
	entries := efivarfs.GetBootOrder()
	if len(entries) != 5 {
		t.Fatalf("incorrect number of boot entries")
	}
}

func TestGetBootEntry(t *testing.T) {
	efivarfs := NewTestFS().
		With(
			fstest.MapFS{
				"/sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c": {Data: []byte{
					0x07, 0x00, 0x00, 0x00, 0x01, 0x00,
				}},
				"/sys/firmware/efi/efivars/Boot0001-8be4df61-93ca-11d2-aa0d-00e098032b8c": {Data: []byte{0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x74, 0x00, 0x4c, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x75, 0x00, 0x78, 0x00, 0x20, 0x00, 0x42, 0x00, 0x6f, 0x00, 0x6f, 0x00, 0x74, 0x00, 0x20, 0x00, 0x4d, 0x00, 0x61, 0x00, 0x6e, 0x00, 0x61, 0x00, 0x67, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x04, 0x01, 0x2a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xf8, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xda, 0x34, 0xa8, 0x08, 0x99, 0xaa, 0x44, 0xb6, 0x7c, 0xd8, 0x06, 0x2c, 0x5a, 0x5c, 0x10, 0x02, 0x02, 0x04, 0x04, 0x46, 0x00, 0x5c, 0x00, 0x45, 0x00, 0x46, 0x00, 0x49, 0x00, 0x5c, 0x00, 0x73, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6d, 0x00, 0x64, 0x00, 0x5c, 0x00, 0x73, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6d, 0x00, 0x64, 0x00, 0x2d, 0x00, 0x62, 0x00, 0x6f, 0x00, 0x6f, 0x00, 0x74, 0x00, 0x78, 0x00, 0x36, 0x00, 0x34, 0x00, 0x2e, 0x00, 0x65, 0x00, 0x66, 0x00, 0x69, 0x00, 0x00, 0x00, 0x7f, 0xff, 0x04, 0x00}},
			},
		).
		Open()
	entry, err := efivarfs.GetBootEntry("Boot0001")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if entry.Description != "Linux Boot Manager" {
		t.Fatalf("expected 'Linux Boot Manager' got '%s' instead", entry.Description)
	}

	if entry.FilePath[1].Format() != "File(\\EFI\\systemd\\systemd-bootx64.efi)" {
		t.Fatalf("expected filepath got '%s' instead", entry.FilePath[1].Format())
	}
}

func TestGetLoaderEntrySelected(t *testing.T) {
	efivarfs := NewTestFS().
		With(
			fstest.MapFS{
				"/sys/firmware/efi/efivars/LoaderEntrySelected-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f": {Data: []byte{0x06, 0x00, 0x00, 0x00, 0x61, 0x00, 0x72, 0x00, 0x63, 0x00, 0x68, 0x00, 0x2d, 0x00, 0x6c, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x75, 0x00, 0x78, 0x00, 0x2e, 0x00, 0x65, 0x00, 0x66, 0x00, 0x69, 0x00, 0x00, 0x00}},
			},
		).
		Open()
	entry, err := efivarfs.GetLoaderEntrySelected()
	if err != nil {
		t.Fatalf("%v", err)
	}

	if entry != "arch-linux.efi" {
		t.Fatalf("entry does not match the loader entry")
	}
}

var testvar = efivar.Efivar{
	Name: "TestVar",
	GUID: util.StringToGUID("2b0f2e5c-6a51-4d63-9f3a-9b1f6c1c7a10"),
	Attributes: attributes.EFI_VARIABLE_NON_VOLATILE |
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
		attributes.EFI_VARIABLE_RUNTIME_ACCESS,
}

func TestRemoveEfivar(t *testing.T) {
	efivarfs := NewTestFS().Open()

	data := efivar.Efibytes("some data")
	if err := efivarfs.WriteVar(testvar, data); err != nil {
		t.Fatalf("encountered error: %v", err)
	}
	if err := efivarfs.RemoveVar(testvar); err != nil {
		t.Fatalf("encountered error: %v", err)
	}

	var rb efivar.Efibytes
	if err := efivarfs.GetVar(testvar, &rb); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected the variable to be gone, got %v", err)
	}
	if err := efivarfs.RemoveVar(testvar); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist removing a missing variable, got %v", err)
	}
}

func TestWriteEfivarReplaces(t *testing.T) {
	efivarfs := NewTestFS().Open()

	for _, data := range []efivar.Efibytes{efivar.Efibytes("a longer value"), efivar.Efibytes("short")} {
		if err := efivarfs.WriteVar(testvar, data); err != nil {
			t.Fatalf("encountered error: %v", err)
		}
		var rb efivar.Efibytes
		if err := efivarfs.GetVar(testvar, &rb); err != nil {
			t.Fatalf("encountered error: %v", err)
		}
		if !bytes.Equal(rb, data) {
			t.Fatalf("expected %q got %q", data, rb)
		}
	}
}

func TestSetDir(t *testing.T) {
	dir := t.TempDir()
	efivarfs := efivarfs.NewFS().SetDir(dir).Open()

	for _, data := range []efivar.Efibytes{efivar.Efibytes("a longer value"), efivar.Efibytes("short")} {
		if err := efivarfs.WriteVar(testvar, data); err != nil {
			t.Fatalf("encountered error: %v", err)
		}
	}

	b, err := os.ReadFile(filepath.Join(dir, "TestVar-2b0f2e5c-6a51-4d63-9f3a-9b1f6c1c7a10"))
	if err != nil {
		t.Fatalf("encountered error: %v", err)
	}
	if want := append([]byte{0x07, 0x00, 0x00, 0x00}, "short"...); !bytes.Equal(b, want) {
		t.Fatalf("expected %x got %x", want, b)
	}

	var rb efivar.Efibytes
	if err := efivarfs.GetVar(testvar, &rb); err != nil || string(rb) != "short" {
		t.Fatalf("expected 'short' got '%s' (%v)", rb, err)
	}
	if err := efivarfs.RemoveVar(testvar); err != nil {
		t.Fatalf("encountered error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "TestVar-2b0f2e5c-6a51-4d63-9f3a-9b1f6c1c7a10")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected the file to be gone, got %v", err)
	}
}

// Needs CAP_LINUX_IMMUTABLE and a file system with the immutable bit (tmpfs
// has it since Linux 6.0); skipped otherwise.
func TestUnsetImmutable(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "TestVar-2b0f2e5c-6a51-4d63-9f3a-9b1f6c1c7a10")
	if err := os.WriteFile(file, []byte{0x07, 0x00, 0x00, 0x00, 0x01}, 0644); err != nil {
		t.Fatal(err)
	}
	if err := attr.SetImmutable(file); err != nil {
		t.Skipf("no immutable bit here: %v", err)
	}
	t.Cleanup(func() { attr.UnsetImmutable(file) })

	checked := efivarfs.NewFS().SetDir(dir).CheckImmutable().Open()
	if err := checked.WriteVar(testvar, efivar.Efibytes("new")); !errors.Is(err, efivarfs.ErrImmutable) {
		t.Fatalf("expected ErrImmutable, got %v", err)
	}
	if err := checked.RemoveVar(testvar); !errors.Is(err, efivarfs.ErrImmutable) {
		t.Fatalf("expected ErrImmutable, got %v", err)
	}

	unset := efivarfs.NewFS().SetDir(dir).UnsetImmutable().Open()
	if err := unset.WriteVar(testvar, efivar.Efibytes("new")); err != nil {
		t.Fatalf("encountered error: %v", err)
	}
	if err := attr.IsImmutable(file); !errors.Is(err, attr.ErrIsImmutable) {
		t.Fatalf("expected the immutable bit to be set again, got %v", err)
	}
	var rb efivar.Efibytes
	if err := unset.GetVar(testvar, &rb); err != nil || string(rb) != "new" {
		t.Fatalf("expected 'new' got '%s' (%v)", rb, err)
	}
	if err := unset.RemoveVar(testvar); err != nil {
		t.Fatalf("encountered error: %v", err)
	}
}
