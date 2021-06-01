package util

import (
	"bytes"
	"testing"
)

func TestParseValidUtf16String(t *testing.T) {
	// This is "arch.efi", as encoded by a Dell laptop's firmware.
	value := []byte{
		97,
		0,
		114,
		0,
		99,
		0,
		104,
		0,
		46,
		0,
		101,
		0,
		102,
		0,
		105,
		0,
		0,
		0,
	}
	buffer := bytes.NewBuffer(value)

	expected := "arch.efi"
	actual, err := ParseUtf16Var(buffer)

	if err != nil {
		t.Fatal(err)
	}

	if actual != expected {
		t.Fatalf(
			"ParseUtf16Var(%s) returned %v (%v), expected %v (%v).",
			value,
			actual,
			[]byte(actual),
			expected,
			[]byte(expected),
		)
	}

}

func TestParseInvalidUtf16String(t *testing.T) {
	// This is "arch.efi", missing the final null strings.
	value := []byte{
		97,
		0,
		114,
		0,
		99,
		0,
		104,
		0,
		46,
		0,
		101,
		0,
		102,
		0,
		105,
		0,
	}
	buffer := bytes.NewBuffer(value)

	_, err := ParseUtf16Var(buffer)
	if err == nil {
		t.Fatalf("ParseUtf16Var did not err with a non-null-terminated string.")
	}

}
