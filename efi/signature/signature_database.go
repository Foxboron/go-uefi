package signature

import "github.com/foxboron/goefi/efi/util"

// Section 32.6 - Code Definition
// Section 32.6.1 - UEFI Variable GUID & Variable Name
// page 1728
var (
	EFI_IMAGE_SECURITY_DATABASE_GUID = util.EFIGUID{0xd719b2cb, 0x3d3a, 0x4596, [8]uint8{0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f}}
	IMAGE_SECURITY_DATABASE          = "db"
	IMAGE_SECURITY_DATABASE1         = "dbx"
	IMAGE_SECURITY_DATABASE2         = "dbt"
	IMAGE_SECURITY_DATABASE3         = "dbr"
)
