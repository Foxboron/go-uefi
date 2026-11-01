package fswrapper

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strconv"
	"testing"

	"github.com/spf13/afero"
)

type zeroSizeFS struct{ afero.Fs }
type zeroSizeFile struct{ afero.File }
type zeroSizeInfo struct{ os.FileInfo }

func (f zeroSizeFS) Open(name string) (afero.File, error) {
	file, err := f.Fs.Open(name)
	if err != nil {
		return nil, err
	}
	return zeroSizeFile{file}, nil
}

func (f zeroSizeFile) Stat() (os.FileInfo, error) {
	info, err := f.File.Stat()
	if err != nil {
		return nil, err
	}
	return zeroSizeInfo{info}, nil
}

func (zeroSizeInfo) Size() int64 { return 0 }

func TestReadEfivarsFileZeroStatSize(t *testing.T) {
	wrapper := NewMemoryWrapper()
	wrapper.SetFS(zeroSizeFS{afero.NewMemMapFs()})
	want := []byte{1, 2, 3, 4, 5}
	if err := afero.WriteFile(wrapper.fs, "variable", append([]byte{7, 0, 0, 0}, want...), 0600); err != nil {
		t.Fatal(err)
	}
	attrs, data, err := wrapper.ReadEfivarsFile("variable")
	if err != nil {
		t.Fatal(err)
	}
	if attrs != 7 || !bytes.Equal(data.Bytes(), want) {
		t.Fatalf("got attributes %v, data %v", attrs, data.Bytes())
	}
}

func TestParseEfivarsShortSize(t *testing.T) {
	wrapper := NewMemoryWrapper()
	for _, size := range []int{-1, 0, 1, 2, 3} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			_, _, err := wrapper.ParseEfivars(bytes.NewReader([]byte{7, 0, 0, 0, 1}), size)
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("size %d: expected unexpected EOF, got %v", size, err)
			}
		})
	}
}
