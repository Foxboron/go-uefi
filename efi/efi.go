package efi

// Top level API for goefi

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/foxboron/goefi/efi/attributes"
	"github.com/foxboron/goefi/efi/device"
	"github.com/foxboron/goefi/efi/pecoff"
	"github.com/foxboron/goefi/efi/signature"
	"github.com/foxboron/goefi/efi/util"
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

func GetBoorOrder() []string {
	ret := []string{}
	s, _ := attributes.ReadEfivars("BootOrder")
	for i := 0; i < len(s.Data); i += 2 {
		val := binary.BigEndian.Uint16([]byte{s.Data[i+1], s.Data[i]})
		ret = append(ret, fmt.Sprintf("Boot%04x\n", val))
	}
	return ret
}

func GetBootEntry(entry string) *device.EFILoadOption {
	s, _ := attributes.ReadEfivars(entry)
	f := bytes.NewReader(s.Data)
	loadOption := device.ParseEFILoadOption(f)
	loadOption.FilePath = device.ParseDevicePath(f)
	return loadOption
}

// GetSetupMode returns if setup mode has been enabled on the machine.
func GetSetupMode() bool {
	if sm, err := attributes.ReadEfivars("SetupMode"); err == nil {
		if sm.Data[0] == 1 {
			return true
		}
	}
	return false
}

// GetSecureBoot returns if secure boot has been enabled on the machine.
func GetSecureBoot() bool {
	if sm, err := attributes.ReadEfivars("SecureBoot"); err == nil {
		if sm.Data[0] == 1 {
			return true
		}
	}
	return false
}

func GetPK() ([]*signature.SignatureList, error) {
	efivar := "PK"
	s, err := attributes.ReadEfivars(efivar)
	if err != nil {
		log.Fatal(err)
	}
	if (ValidAttributes[efivar] & s.Attributes) != ValidAttributes[efivar] {
		return nil, fmt.Errorf("invalid bitmask")
	}
	siglist := signature.ReadSignatureLists(bytes.NewReader(s.Data))
	return siglist, nil
}

func GetKEK() ([]*signature.SignatureList, error) {
	efivar := "KEK"
	s, err := attributes.ReadEfivars(efivar)
	if err != nil {
		log.Fatal(err)
	}
	if (ValidAttributes[efivar] & s.Attributes) != ValidAttributes[efivar] {
		return nil, fmt.Errorf("invalid bitmask")
	}
	siglist := signature.ReadSignatureLists(bytes.NewReader(s.Data))
	return siglist, nil
}

func Getdb() ([]*signature.SignatureList, error) {
	efivar := "db"
	s, err := attributes.ReadEfivars(efivar)
	if err != nil {
		log.Fatal(err)
	}
	if (ValidAttributes[efivar] & s.Attributes) != ValidAttributes[efivar] {
		return nil, fmt.Errorf("invalid bitmask")
	}
	siglist := signature.ReadSignatureLists(bytes.NewReader(s.Data))
	return siglist, nil
}

func SignEFIVariable(key *rsa.PrivateKey, cert *x509.Certificate, varname string, siglist []byte) []byte {
	attrs := ValidAttributes[varname]
	attrs |= attributes.EFI_VARIABLE_APPEND_WRITE

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
	signedVariable := signature.NewSignedEFIVariable(ctx)
	buf := new(bytes.Buffer)
	signature.WriteEFIVariableAuthencation2(buf, *signedVariable)
	buf.Write(siglist)
	return buf.Bytes()
}

func SignEFIExecutable(key *rsa.PrivateKey, cert *x509.Certificate, file []byte) []byte {
	ctx := pecoff.PECOFFChecksum(file)
	ctx.Cert = cert
	ctx.Key = key
	b := pecoff.SignPECOFF(ctx)
	return b
}

func WriteEFIVariable(variable string, buf []byte) error {
	attrs := ValidAttributes[variable]
	if err := attributes.WriteEfivars(variable, attrs, buf); err != nil {
		return err
	}
	return nil
}
