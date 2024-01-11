package efivarfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"

	"github.com/foxboron/go-uefi/efi/attr"
	"github.com/foxboron/go-uefi/efi/attributes"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/spf13/afero"
)

// This package is the lowest layer of the filesystem abstraction.
// It ensures we have a filesystem api with WriteFile/ReadFile/OpenFile as this
// is not suporting supported by io/fs nor
// afero.Fs at the moment.

// This should largely be considered a patch layer on top of our virtual filesystems!

var (
	errImmutable = attr.ErrIsImmutable
)

// Unsure if we need this
type efifswrappers interface {
	WriteFile(name string, data []byte, perm os.FileMode) error
	ReadFile(name string) ([]byte, error)
	OpenFile(name string, flag int, perm os.FileMode) (io.ReadWriteCloser, error)
	Open(name string) (fs.File, error)
	// MkdirAll(path string, perm os.FileMode) error
}

type FSWrapper struct {
	unsetimmutable bool
	immutable      bool
	fs             afero.Fs
}

func (e *FSWrapper) CheckImmutable() {
	e.immutable = true
}

func (e *FSWrapper) UnsetImmutable() {
	e.unsetimmutable = true
}

func NewMemoryWrapper() *FSWrapper {
	return &FSWrapper{
		unsetimmutable: false,
		immutable:      false,
		fs:             afero.NewMemMapFs(),
	}
}

func NewFSWrapper() *FSWrapper {
	return &FSWrapper{
		unsetimmutable: false,
		immutable:      false,
		fs:             afero.NewOsFs(),
	}
}

func (t *FSWrapper) isimmutable(efivar string) error {
	if !t.immutable {
		return nil
	}
	err := attr.IsImmutable(efivar)
	switch {
	case errors.Is(err, attr.ErrIsImmutable):
		if !t.unsetimmutable {
			return errImmutable
		}
		if err := attr.UnsetImmutable(efivar); err != nil {
			return fmt.Errorf("couldn't unset immutable bit: %w", err)
		}
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	}
	return nil
}

func (t *FSWrapper) WriteFile(name string, data []byte, perm os.FileMode) error {
	if err := t.isimmutable(name); err != nil {
		return err
	}
	f, err := t.fs.Create(name)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}
	return err
}

func (t *FSWrapper) ReadFile(name string) ([]byte, error) {
	f, err := t.fs.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var size int
	if info, err := f.Stat(); err == nil {
		size64 := info.Size()
		if int64(int(size64)) == size64 {
			size = int(size64)
		}
	}
	size++ // one byte for final read at EOF
	if size < 512 {
		size = 512
	}

	data := make([]byte, 0, size)
	for {
		if len(data) >= cap(data) {
			d := append(data[:cap(data)], 0)
			data = d[:len(data)]
		}
		n, err := f.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return data, err
		}
	}
}

func (t *FSWrapper) OpenFile(name string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
	return t.fs.OpenFile(name, flag, perm)
}

func (t *FSWrapper) Open(name string) (fs.File, error) {
	return t.fs.Open(name)
}

func (t *FSWrapper) ParseEfivars(f io.Reader, size int) (attributes.Attributes, *bytes.Buffer, error) {
	var attrs attributes.Attributes
	if err := binary.Read(f, binary.LittleEndian, &attrs); err != nil {
		return 0, nil, fmt.Errorf("could not read file: %w", err)
	}
	buf := make([]byte, size-attributes.SizeofAttributes)
	if err := binary.Read(f, binary.LittleEndian, &buf); err != nil {
		return 0, nil, err
	}
	return attrs, bytes.NewBuffer(buf), nil
}

// For a full path instead of the inferred efivars path
func (t *FSWrapper) ReadEfivarsFile(filename string) (attributes.Attributes, *bytes.Buffer, error) {
	f, err := t.fs.Open(filename)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return 0, nil, fmt.Errorf("could not stat file descriptor: %w", err)
	}
	return t.ParseEfivars(f, int(stat.Size()))
}

func (t *FSWrapper) ReadEfivarsWithGuid(filename string, guid util.EFIGUID) (attributes.Attributes, *bytes.Buffer, error) {
	f := path.Join(attributes.Efivars, fmt.Sprintf("%s-%s", filename, guid.Format()))
	return t.ReadEfivarsFile(f)
}

// Write an EFI variable to sysfs
// TODO: Fix retryable writes
func (t *FSWrapper) WriteEfivarsWithGuid(name string, attrs attributes.Attributes, b []byte, guid util.EFIGUID) error {
	efivar := path.Join(attributes.Efivars, fmt.Sprintf("%s-%s", name, guid.Format()))

	flags := os.O_WRONLY | os.O_CREATE //| os.O_TRUNC
	if attrs&attributes.EFI_VARIABLE_APPEND_WRITE != 0 {
		flags |= os.O_APPEND
	}
	f, err := t.fs.OpenFile(efivar, flags, 0644)
	if err != nil {
		return fmt.Errorf("couldn't open file: %w", err)
	}
	defer f.Close()
	buf := append(attrs.Bytes(), b...)
	if n, err := f.Write(buf); err != nil {
		return fmt.Errorf("couldn't write efi variable: %w", err)
	} else if n != len(buf) {
		return errors.New("could not write the entire buffer")
	}
	return nil
}
