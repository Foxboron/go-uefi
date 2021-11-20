package efi

// Top level API for goefi

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/foxboron/go-uefi/efi/attributes"
	"github.com/foxboron/go-uefi/efi/device"
	"github.com/foxboron/go-uefi/efi/pecoff"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/pkg/errors"
)

// Keeps track of expected attributes for each variable
var ValidAttributes = map[string]attributes.Attributes{
	"SetupMode": attributes.EFI_VARIABLE_NON_VOLATILE |
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS,
	"PK": attributes.EFI_VARIABLE_NON_VOLATILE |
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
		attributes.EFI_VARIABLE_RUNTIME_ACCESS |
		attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
	"KEK": attributes.EFI_VARIABLE_NON_VOLATILE |
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
		attributes.EFI_VARIABLE_RUNTIME_ACCESS |
		attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
	"db": attributes.EFI_VARIABLE_NON_VOLATILE |
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
		attributes.EFI_VARIABLE_RUNTIME_ACCESS |
		attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
	"dbx": attributes.EFI_VARIABLE_NON_VOLATILE |
		attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
		attributes.EFI_VARIABLE_RUNTIME_ACCESS |
		attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
}

func GetBootOrder() []string {
	ret := []string{}
	_, data, _ := attributes.ReadEfivars("BootOrder")
	for i := 0; i < data.Len(); i += 2 {
		b := make([]byte, 2)
		data.Read(b)
		val := binary.BigEndian.Uint16([]byte{b[1], b[0]})
		ret = append(ret, fmt.Sprintf("Boot%04x\n", val))
	}
	return ret
}

func GetBootEntry(entry string) *device.EFILoadOption {
	_, f, _ := attributes.ReadEfivars(entry)
	loadOption := device.ParseEFILoadOption(f)
	loadOption.FilePath = device.ParseDevicePath(f)
	return loadOption
}

// GetSetupMode returns if setup mode has been enabled on the machine.
func GetSetupMode() bool {
	if _, data, err := attributes.ReadEfivars("SetupMode"); err == nil {
		b, _ := data.ReadByte()
		if b == 1 {
			return true
		}
	}
	return false
}

// GetSecureBoot returns if secure boot has been enabled on the machine.
func GetSecureBoot() bool {
	if _, data, err := attributes.ReadEfivars("SecureBoot"); err == nil {
		b, _ := data.ReadByte()
		if b == 1 {
			return true
		}
	}
	return false
}

func GetPK() ([]*signature.SignatureList, error) {
	efivar := "PK"
	attributes, data, err := attributes.ReadEfivars(efivar)
	if err != nil {
		log.Fatal(err)
	}
	if (ValidAttributes[efivar] & attributes) != ValidAttributes[efivar] {
		return nil, fmt.Errorf("invalid bitmask")
	}
	siglist, err := signature.ReadSignatureDatabase(data)
	if err != nil {
		return nil, errors.Wrapf(err, "can't parse Platform Key")
	}
	return siglist, nil
}

func GetKEK() ([]*signature.SignatureList, error) {
	efivar := "KEK"
	attr, data, err := attributes.ReadEfivars(efivar)
	if err != nil {
		log.Fatal(err)
	}
	if (ValidAttributes[efivar] & attr) != ValidAttributes[efivar] {
		return nil, fmt.Errorf("invalid bitmask")
	}
	siglist, err := signature.ReadSignatureDatabase(data)
	if err != nil {
		return nil, errors.Wrapf(err, "can't parse Key Exchange key")
	}
	return siglist, nil
}

func Getdb() (*signature.SignatureDatabase, error) {
	efivar := "db"
	attr, data, err := attributes.ReadEfivars(efivar)
	if err != nil {
		return nil, err
	}
	if (ValidAttributes[efivar] & attr) != ValidAttributes[efivar] {
		return nil, fmt.Errorf("invalid bitmask")
	}
	siglist, err := signature.ReadSignatureDatabase(data)
	if err != nil {
		return nil, errors.Wrapf(err, "can't parse database key")
	}
	return &siglist, nil
}

func SignEFIExecutable(key crypto.Signer, cert *x509.Certificate, file []byte) ([]byte, error) {
	ctx := pecoff.PECOFFChecksum(file)
	sig, err := pecoff.CreateSignature(ctx, cert, key)
	if err != nil {
		return nil, err
	}
	b, err := pecoff.AppendToBinary(ctx, sig)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func SignEFIVariableWithAttr(key crypto.Signer, cert *x509.Certificate, varname string, siglist []byte, attr attributes.Attributes) ([]byte, error) {
	attrs := ValidAttributes[varname]
	attrs |= attr

	var guid util.EFIGUID

	if ok := attributes.ImageSecurityDatabases[varname]; ok {
		guid = attributes.EFI_IMAGE_SECURITY_DATABASE_GUID
	} else {
		guid = attributes.EFI_GLOBAL_VARIABLE
	}

	ctx := &signature.EFIVariableSigningContext{
		Cert:    cert,
		Key:     key,
		Varname: []byte(varname),
		Guid:    guid,
		Attr:    attrs,
		Data:    siglist,
	}
	signedVariable, err := signature.NewSignedEFIVariable(ctx)
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	signature.WriteEFIVariableAuthencation2(buf, *signedVariable)
	buf.Write(siglist)
	return buf.Bytes(), err
}

func SignEFIVariable(key crypto.Signer, cert *x509.Certificate, varname string, siglist []byte) ([]byte, error) {
	return SignEFIVariableWithAttr(key, cert, varname, siglist, 0)
}

func WriteEFIVariable(variable string, buf []byte) error {
	attrs := ValidAttributes[variable]
	if err := attributes.WriteEfivars(variable, attrs, buf); err != nil {
		return err
	}
	return nil
}

// Return the boot entry which is currently booted.
func GetCurrentlyBootedEntry() (string, error) {
	_, data, err := attributes.ReadEfivarsWithGuid(
		"LoaderEntrySelected",
		*util.StringToGUID("4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"),
	)
	if err != nil {
		return "", err
	}

	name, err := util.ParseUtf16Var(data)
	if err != nil {
		return "", err
	}

	return name, nil
}
