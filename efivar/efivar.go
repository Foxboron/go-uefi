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
	// Whether the platform firmware is operating in Secure boot
	// mode (1) or not (0). All other values are reserved. Should be
	// treated as read-only.
	SecureBoot = Efivar{"SecureBoot", util.StringToGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// Whether the system should require authentication on
	// SetVariable() requests to Secure Boot policy variables (0) or
	// not (1). Should be treated as read-only.
	// The system is in "Setup Mode" when SetupMode==1,
	// AuditMode==0, and DeployedMode==0.
	SetupMode = Efivar{"SetupMode", util.StringToGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// The public Platform Key.
	PK = Efivar{"PK", util.StringToGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
		attributes.EFI_VARIABLE_NON_VOLATILE |
			attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS |
			attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS}

	// The OEM's default public Platform Key. Should be treated as
	// read-only
	PKDefault = Efivar{"PKDefault", util.StringToGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
		attributes.EFI_VARIABLE_NON_VOLATILE |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// The Key Exchange Key Signature Database.
	KEK = Efivar{"KEK", util.StringToGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
		attributes.EFI_VARIABLE_NON_VOLATILE |
			attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS |
			attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS}

	// The OEM's default Key Exchange Key Signature Database.  Should be treated
	// as read-only.
	KEKDefault = Efivar{"KEKDefault", util.StringToGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
		attributes.EFI_VARIABLE_NON_VOLATILE |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	Db = Efivar{"db", util.StringToGUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f"),
		attributes.EFI_VARIABLE_NON_VOLATILE |
			attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS |
			attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS}

	// The OEM's default secure boot signature store. Should be treated as
	// read-only.
	DbDefault = Efivar{"dbDefault", util.StringToGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
		attributes.EFI_VARIABLE_NON_VOLATILE |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	Dbx = Efivar{"dbx", util.StringToGUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f"),
		attributes.EFI_VARIABLE_NON_VOLATILE |
			attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS |
			attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS}

	// The OEM's default secure boot blacklist signature store.
	// Should be treated as read-only.
	DbxDefault = Efivar{"dbxDefault", util.StringToGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
		attributes.EFI_VARIABLE_NON_VOLATILE |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// The boot option that was selected for the current boot.
	BootCurrent = Efivar{"BootCurrent", util.StringToGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// The boot option that was selected for the current boot.
	BootNext = Efivar{"BootNext", util.StringToGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
		attributes.EFI_VARIABLE_NON_VOLATILE |
			attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// The ordered boot option load list.
	BootOrder = Efivar{"BootOrder", util.StringToGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
		attributes.EFI_VARIABLE_NON_VOLATILE |
			attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// A boot load option. #### is a printed hex value. No 0x or h is
	// included in the hex value.
	BootEntry = Efivar{"Boot####", util.StringToGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
		attributes.EFI_VARIABLE_NON_VOLATILE |
			attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// LoaderTimeInitUSec contains the timestamp in microseconds when the loader
	// was initialized.  This value is the time spent in the firmware for
	// initialization, it is formatted as numeric, NUL-terminated, decimal string,
	// in UTF-16.
	LoaderTimeInitUSec = Efivar{"LoaderTimeInitUSec", util.StringToGUID("4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"),
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// LoaderTimeExecUSec contains the timestamp in microseconds
	// when the loader finished its work and is about to execute the kernel. The
	// time spent in the loader is the difference between LoaderTimeExecUSec and
	// LoaderTimeInitUSec. This value is formatted the same way as
	// LoaderTimeInitUSec.
	LoaderTimeExecUSec = Efivar{"LoaderTimeExecUSec", util.StringToGUID("4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"),
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// LoaderDevicePartUUID contains the partition GUID of the ESP the boot loader
	// was run from formatted as NUL-terminated UTF16 string, in normal GUID
	// syntax.
	LoaderDevicePartUUID = Efivar{"LoaderDevicePartUUID", util.StringToGUID("4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"),
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// LoaderConfigTimeout contains the boot menu timeout
	// currently in use. It may be modified both by the boot loader and by the
	// host. The value should be formatted as numeric, NUL-terminated, decimal
	// string, in UTF-16. The time is specified in seconds. In addition some
	// non-numeric string values are also accepted. A value of menu-force will
	// disable the timeout and show the menu indefinitely. If set to 0 or
	// menu-hidden the default entry is booted immediately without showing a menu.
	// Unless a value of menu-disabled is set, the boot loader should provide a way
	// to interrupt this by for example listening for key presses for a brief
	// moment before booting.
	LoaderConfigTimeout = Efivar{"LoaderConfigTimeout", util.StringToGUID("4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"),
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// LoaderConfigTimeoutOneShot contains a boot menu timeout for a single
	// following boot. It is set by the OS in order to request display of the boot
	// menu on the following boot. When set overrides LoaderConfigTimeout. It is
	// removed automatically after being read by the boot loader, to ensure it
	// only takes effect a single time. This value is formatted the same way as
	// LoaderConfigTimeout. If set to 0 the boot menu timeout is turned off, and
	// the menu is shown indefinitely.
	LoaderConfigTimeoutOneShot = Efivar{"LoaderConfigTimeoutOneShot", util.StringToGUID("4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"),
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// LoaderEntries may contain a series of boot loader entry identifiers, one after
	// the other, each individually NUL terminated. This may be used to let the OS know
	// which boot menu entries were discovered by the boot loader. A boot loader entry
	// identifier should be a short, non-empty alphanumeric string (possibly containing
	// -, too). The list should be in the order the entries are shown on screen during
	// boot. See below regarding a recommended vocabulary for boot loader entry
	// identifiers.
	LoaderEntries = Efivar{"LoaderEntries", util.StringToGUID("4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"),
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// LoaderEntryDefault contains the default boot loader entry to use. It
	// contains a NUL-terminated boot loader entry identifier.
	LoaderEntryDefault = Efivar{"LoaderEntryDefault", util.StringToGUID("4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"),
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// LoaderEntryOneShot contains the default boot loader entry to use for a
	// single following boot. It is set by the OS in order to request booting into
	// a specific menu entry on the following boot. When set overrides
	// LoaderEntryDefault. It is removed automatically after being read by the
	// boot loader, to ensure it only takes effect a single time. This value is
	// formatted the same way as LoaderEntryDefault.
	LoaderEntryOneShot = Efivar{"LoaderEntryOneShot", util.StringToGUID("4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"),
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// LoaderEntrySelected contains the boot loader entry identifier that was
	// booted. It is set by the boot loader and read by the OS in order to
	// identify which entry has been used for the current boot.
	LoaderEntrySelected = Efivar{"LoaderEntrySelected", util.StringToGUID("4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"),
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// LoaderFeatures contains a 64-bit unsigned integer with a number
	// of flags bits that are set by the boot loader and passed to the OS and indicate
	// the features the boot loader supports. Specifically, the following bits are
	// 1 << 0 → The boot loader honours LoaderConfigTimeout when set.
	// 1 << 1 → The boot loader honours LoaderConfigTimeoutOneShot when set.
	// 1 << 2 → The boot loader honours LoaderEntryDefault when set.
	// 1 << 3 → The boot loader honours LoaderEntryOneShot when set.
	// 1 << 4 → The boot loader supports boot counting as described in Automatic Boot Assessment.
	// 1 << 5 → The boot loader supports looking for boot menu entries in the Extended Boot Loader Partition.
	// 1 << 6 → The boot loader supports passing a random seed to the OS.
	// 1 << 13 → The boot loader honours menu-disabled option when set.// defined:
	LoaderFeatures = Efivar{"LoaderFeatures", util.StringToGUID("4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"),
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}

	// LoaderSystemToken contains binary random data, persistently set by the OS
	// installer. Boot loaders that support passing random seeds to the OS should
	// use this data and combine it with the random seed file read from the ESP.
	// By combining this random data with the random seed read off the disk before
	// generating a seed to pass to the OS and a new seed to store in the ESP the
	// boot loader can protect itself from situations where “golden” OS images
	// that include a random seed are replicated and used on multiple systems.
	// Since the EFI variable storage is usually independent (i.e. in physical
	// NVRAM) of the ESP file system storage, and only the latter is part of
	// “golden” OS images, this ensures that different systems still come up with
	// different random seeds. Note that the LoaderSystemToken is generally only
	// written once, by the OS installer, and is usually not touched after that.
	LoaderSystemToken = Efivar{"LoaderSystemToken", util.StringToGUID("4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"),
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS}
)

// Marshallable is an interface to marshal efi variables
type Marshallable interface {
	Marshal(buf *bytes.Buffer)
	Bytes() []byte
}

// Unmarshallable is an interface to unmarshal efi variables
type Unmarshallable interface {
	Unmarshal(data *bytes.Buffer) error
}

// Some basic UEFI types

type Efistring string

func (es *Efistring) Unmarshal(b *bytes.Buffer) error {
	bb := util.ReadNullString(b)
	s, err := util.ParseUtf16Var(bytes.NewBuffer(bb))
	if err != nil {
		return err
	}
	*es = Efistring(s)
	return nil
}
