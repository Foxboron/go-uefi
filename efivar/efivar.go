package efivar

import (
	"bytes"

	"github.com/foxboron/go-uefi/efi/attributes"
	"github.com/foxboron/go-uefi/efi/util"
)

type Efivar struct {
	Name       string
	GUID       *util.EFIGUID
	Attributes attributes.Attributes
}

// Definitions for standard EFI variables
var (
	SecureBoot = Efivar{"SecureBoot", util.StringToGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}
	SetupMode = Efivar{"SetupMode", util.StringToGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}
	PK = Efivar{"db", util.StringToGUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f"),
		attributes.EFI_VARIABLE_NON_VOLATILE |
			attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS |
			attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS}
	KEK = Efivar{"db", util.StringToGUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f"),
		attributes.EFI_VARIABLE_NON_VOLATILE |
			attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS |
			attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS}
	Db = Efivar{"db", util.StringToGUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f"),
		attributes.EFI_VARIABLE_NON_VOLATILE |
			attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS |
			attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS}
	Dbx = Efivar{"db", util.StringToGUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f"),
		attributes.EFI_VARIABLE_NON_VOLATILE |
			attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS |
			attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS}
)

// Marshallable is an interface to marshal efi variables
type Marshallable interface {
	Marshal(buf *bytes.Buffer)
}

// Unmarshallable is an interface to unmarshal efi variables
type Unmarshallable interface {
	Unmarshal(data *bytes.Buffer) error
}
