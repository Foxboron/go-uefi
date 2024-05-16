package testfs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing/fstest"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efivar"
	"github.com/foxboron/go-uefi/efivarfs"
	"github.com/foxboron/go-uefi/efivarfs/fswrapper"
	"github.com/spf13/afero"
)

// TestFS deals with providing a layer controllable layer we can use for
// integration tests.

// This is the a wrapper around MapFS to easily inject data and convert it to afero.fs
type TestFS struct {
	*efivarfs.EFIFS
	mapfs fstest.MapFS
}

func NewTestFS() *TestFS {
	return &TestFS{
		EFIFS: &efivarfs.EFIFS{fswrapper.NewMemoryWrapper()},
		mapfs: fstest.MapFS{},
	}
}

// Convert fstest.MapFS to afero.Fs
func fromMapFS(files fstest.MapFS) afero.Fs {
	memfs := afero.NewMemMapFs()
	for name, file := range files {
		if file.Mode.IsDir() {
			memfs.MkdirAll(name, file.Mode.Perm())
			continue
		}
		// We ignore the error here as if the directory exists it should be fine.
		memfs.MkdirAll(filepath.Dir(name), 0644)
		f, err := memfs.OpenFile(name, os.O_CREATE, file.Mode.Perm())
		if err != nil {
			continue
		}
		f.Write(file.Data)
		f.Close()
	}
	return memfs
}

// func (f *Testfs) ToFS() EFIFs {
// 	return &FS{
// 		unsetimmutable: false,
// 		immutable:      false,
// 		fs:             f.ToAfero(),
// 	}
// }

// With allows you to compose several overlay files into the in-memory filesystem.
func (f *TestFS) With(files ...fstest.MapFS) *TestFS {
	for _, mapfs := range files {
		for path, file := range mapfs {
			f.mapfs[path] = file
		}
	}
	return f
}

// Open opens TestFS as Efivarfs
func (f *TestFS) Open() *efivarfs.Efivarfs {
	overlayfs := fromMapFS(f.mapfs)
	// I don't think this was a good idea
	f.SetFS(overlayfs)
	return &efivarfs.Efivarfs{f}
}

// WriteVar is a shim around EFIFS.WriteVar and ensures variables written to the
// in-memory filesystem is "unwrapped" of things like authentication headers if
// they exist.
func (f *TestFS) WriteVar(v efivar.Efivar, t efivar.Marshallable) error {
	switch v.Name {
	case "PK", "KEK", "db", "dbx":
		// Unwraps the auth header
		var b bytes.Buffer
		var sea signature.EFIVariableAuthentication2
		t.Marshal(&b)
		// Only unwrap the Auth header if it exists
		if err := sea.Unmarshal(&b); err == nil {
			var sb signature.SignatureDatabase
			sb.Unmarshal(&b)
			t = &sb
		}
	}
	return f.EFIFS.WriteVar(v, t)
}
