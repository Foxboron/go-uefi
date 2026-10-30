package fswrapper

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
	SetFS(fs afero.Fs)
	// MkdirAll(path string, perm os.FileMode) error
}

type FSWrapper struct {
	unsetimmutable bool
	immutable      bool
	fs             afero.Fs
	dir            string
}

func (e *FSWrapper) SetFS(fs afero.Fs) {
	e.fs = fs
}

// SetDir sets the directory the variables are in, efivarfs' mount point by
// default (attributes.Efivars).
func (e *FSWrapper) SetDir(dir string) {
	e.dir = dir
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
		dir:            attributes.Efivars,
	}
}

func NewFSWrapper() *FSWrapper {
	return &FSWrapper{
		unsetimmutable: false,
		immutable:      false,
		fs:             afero.NewOsFs(),
		dir:            attributes.Efivars,
	}
}

// isimmutable checks the immutable bit before a write or a removal. With
// UnsetImmutable it is unset, and the function returned sets it again; it is
// called whether the write succeeded or not. The bit is a file attribute of
// the operating system's file systems: other file systems have none.
func (t *FSWrapper) isimmutable(efivar string) (func() error, error) {
	restore := func() error { return nil }
	if !t.immutable && !t.unsetimmutable {
		return restore, nil
	}
	if _, ok := t.fs.(*afero.OsFs); !ok {
		return restore, nil
	}
	err := attr.IsImmutable(efivar)
	switch {
	case errors.Is(err, attr.ErrIsImmutable):
		if !t.unsetimmutable {
			return restore, fmt.Errorf("%s: %w", efivar, errImmutable)
		}
		if err := attr.UnsetImmutable(efivar); err != nil {
			return restore, fmt.Errorf("couldn't unset immutable bit: %w", err)
		}
		restore = func() error {
			if err := attr.SetImmutable(efivar); err != nil {
				return fmt.Errorf("couldn't set immutable bit again: %w", err)
			}
			return nil
		}
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return restore, err
	}
	return restore, nil
}

func (t *FSWrapper) WriteFile(name string, data []byte, perm os.FileMode) (err error) {
	restore, err := t.isimmutable(name)
	if err != nil {
		return err
	}
	defer func() {
		if err1 := restore(); err1 != nil && err == nil {
			err = err1
		}
	}()
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

// EfivarPath is the file of the variable name with the vendor guid
func (t *FSWrapper) EfivarPath(name string, guid util.EFIGUID) string {
	return path.Join(t.dir, fmt.Sprintf("%s-%s", name, guid.Format()))
}

func (t *FSWrapper) ReadEfivarsWithGuid(filename string, guid util.EFIGUID) (attributes.Attributes, *bytes.Buffer, error) {
	return t.ReadEfivarsFile(t.EfivarPath(filename, guid))
}

// Write an EFI variable to sysfs. efivarfs replaces the variable with each
// write, and takes it whole or not at all; the file is truncated too, for any
// other file system.
// TODO: Fix retryable writes
func (t *FSWrapper) WriteEfivarsWithGuid(name string, attrs attributes.Attributes, b []byte, guid util.EFIGUID) (err error) {
	efivar := t.EfivarPath(name, guid)

	restore, err := t.isimmutable(efivar)
	if err != nil {
		return err
	}
	defer func() {
		if err1 := restore(); err1 != nil && err == nil {
			err = err1
		}
	}()

	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if attrs&attributes.EFI_VARIABLE_APPEND_WRITE != 0 {
		flags = os.O_WRONLY | os.O_CREATE | os.O_APPEND
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

// Remove an EFI variable from sysfs. A variable that does not exist is an
// error, os.ErrNotExist.
func (t *FSWrapper) RemoveEfivarsWithGuid(name string, guid util.EFIGUID) (err error) {
	efivar := t.EfivarPath(name, guid)

	restore, err := t.isimmutable(efivar)
	if err != nil {
		return err
	}
	if err := t.fs.Remove(efivar); err != nil {
		// The variable is still there: so is its immutable bit
		if err1 := restore(); err1 != nil {
			return errors.Join(err, err1)
		}
		return err
	}
	return nil
}
