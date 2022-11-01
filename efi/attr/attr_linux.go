package attr

import (
	"os"

	"golang.org/x/sys/unix"
)

// GetAttr retrieves the attributes of a file on a linux filesystem
func GetAttrFromFile(f *os.File) (int32, error) {
	attr_int, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	return int32(attr_int), err
}

// SetAttr sets the attributes of a file on a linux filesystem to the given value
func SetAttrOnFile(f *os.File, attr int32) error {
	if err := unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, int(attr)); err != nil {
		return err
	}
	return nil
}
