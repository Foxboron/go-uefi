package efitest

import "testing/fstest"

func SecureBootOff() fstest.MapFS {
	return fstest.MapFS{
		"/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c": {
			Data: []byte{0x6, 0x0, 0x0, 0x0, 0x0}},
	}
}

func SecureBootOn() fstest.MapFS {
	return fstest.MapFS{
		"/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c": {
			Data: []byte{0x6, 0x0, 0x0, 0x0, 0x1}},
	}
}

func SetUpModeOn() fstest.MapFS {
	return fstest.MapFS{
		"/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c": {
			Data: []byte{0x6, 0x0, 0x0, 0x0, 0x1}},
	}
}

func SetUpModeOff() fstest.MapFS {
	return fstest.MapFS{
		"/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c": {
			Data: []byte{0x6, 0x0, 0x0, 0x0, 0x1}},
	}
}
