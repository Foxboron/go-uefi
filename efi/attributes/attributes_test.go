package attributes

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strconv"
	"testing"

	"github.com/foxboron/go-uefi/efi/fs"
	"github.com/spf13/afero"
)

func TestParseEfivarsShortSize(t *testing.T) {
	for _, size := range []int{-1, 0, 1, 2, 3} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			_, _, err := ParseEfivars(bytes.NewReader([]byte{7, 0, 0, 0, 1}), size)
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("size %d: expected unexpected EOF, got %v", size, err)
			}
		})
	}
}

// efivarfs can report a zero size for a variable that still has readable data.
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
	previous := fs.Fs
	t.Cleanup(func() { fs.Fs = previous })
	fs.Fs = zeroSizeFS{afero.NewMemMapFs()}
	want := []byte{1, 2, 3, 4, 5}
	if err := afero.WriteFile(fs.Fs, "variable", append([]byte{7, 0, 0, 0}, want...), 0600); err != nil {
		t.Fatal(err)
	}
	attrs, data, err := ReadEfivarsFile("variable")
	if err != nil {
		t.Fatal(err)
	}
	if attrs != 7 || !bytes.Equal(data.Bytes(), want) {
		t.Fatalf("got attributes %v, data %v", attrs, data.Bytes())
	}
}

func TestParseEfivarsBounds(t *testing.T) {
	for _, tt := range []struct {
		name string
		data []byte
		size int
		want []byte
		err  error
	}{
		{"empty", nil, 4, nil, io.EOF},
		{"short attributes", []byte{7, 0}, 4, nil, io.ErrUnexpectedEOF},
		{"attributes only", []byte{7, 0, 0, 0}, 4, []byte{}, nil},
		{"short payload", []byte{7, 0, 0, 0, 1}, 6, nil, io.ErrUnexpectedEOF},
		{"bounded payload", []byte{7, 0, 0, 0, 1, 2, 3}, 6, []byte{1, 2}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			attrs, data, err := ParseEfivars(bytes.NewReader(tt.data), tt.size)
			if !errors.Is(err, tt.err) {
				t.Fatalf("expected %v, got %v", tt.err, err)
			}
			if err == nil && (attrs != 7 || !bytes.Equal(data.Bytes(), tt.want)) {
				t.Fatalf("got attributes %v, data %v", attrs, data.Bytes())
			}
		})
	}
}
