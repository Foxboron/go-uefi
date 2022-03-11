package attr

import (
	"os"
)

// Stub implementation for OSX
func GetAttrFromFile(f *os.File) (int32, error) {
	return 0, nil
}

// Stub implementation for OSX
func SetAttrOnFile(f *os.File, attr int32) error {
	return nil
}
