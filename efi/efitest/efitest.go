package efitest

import (
	"path/filepath"
	"testing/fstest"

	"github.com/foxboron/go-uefi/efi/fs"
	"github.com/spf13/afero"
)

// Convert fstest.MapFS to afero.Fs
func FromMapFS(files fstest.MapFS) afero.Fs {
	memfs := afero.NewMemMapFs()
	for name, file := range files {
		memfs.MkdirAll(filepath.Dir(name), 0644)
		f, err := memfs.Create(name)
		if err != nil {
			continue
		}
		f.Write(file.Data)
		f.Close()
	}
	return memfs
}

type FSState struct {
	fs fstest.MapFS
}

func (f *FSState) ToAfero() afero.Fs {
	return FromMapFS(f.fs)
}

func (f *FSState) SetFS() *FSState {
	fs.SetFS(f.ToAfero())
	return f
}

func (f *FSState) With(files ...fstest.MapFS) *FSState {
	for _, mapfs := range files {
		for path, file := range mapfs {
			f.fs[path] = file
		}
	}
	return f
}

func NewFS() *FSState {
	return &FSState{fs: fstest.MapFS{}}
}
