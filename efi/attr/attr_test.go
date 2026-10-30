package attr

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestIsImmutableMissingFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "missing")
	if err := IsImmutable(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("checking the immutable bit created the file")
	}
}
