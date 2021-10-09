go-uefi
=======

A UEFI library written to interact with Linux efivars. The goal is to provide a
Go library to enable application authors to better utilize secure boot and UEFI.
This also includes unit-testing to ensure the library is compatible with
existing tools, and integration tests to ensure the library is able of deal with
future UEFI revisions.


# Features
* Implements most Secure Boot relevant structs as defined in UEFI Spec Version 2.8 Errata A (February 14th 2020).
* PE/COFF Checksumming.
* Microsoft Authenticode signing.
* Working with EFI_SIGNATURE_LIST and EFI_SIGNATURE_DATABASE.
* Integration tests utilizing [vmtest](https://github.com/anatol/vmtest) and tianocore.
* Virtual filesystem support for easier testing.


# Examples

Some example can be found under `cmd/`.


## Append signatures to db

```go
package main
import (
	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
)

var (
    cert, _ = util.ReadKeyFromFile("signing.key")
    key, _ = util.ReadCertFromFile("signing.cert")
    sigdata = signature.SignatureData{
	    Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}},
	    Data:  []uint8{}}
)

func main() {
    db, _ := efi.Getdb()
    db.AppendSignature(signature.CERT_SHA256_GUID, &sigdata)
    buf, _ := efi.SignEFIVariable(key, cert, "db", db.Bytes())
    efi.WriteEFIVariable("db", buf)
}
```

## Sign UEFI binary
```go
package main
import (
	"github.com/foxboron/go-uefi/efi/pecoff"
	"github.com/foxboron/go-uefi/efi/util"
)

var (
	key, _ := util.ReadKeyFromFile("signing.key")
	cert, _ := util.ReadCertFromFile("signing.cert")
)

func main(){
	peFile, _ := os.ReadFile("somefile")
	ctx := pecoff.PECOFFChecksum(peFile)
	sig, _ := pecoff.CreateSignature(ctx, Cert, Key)
	b, _ := pecoff.AppendToBinary(ctx, sig)
	os.WriteFile("somefile.signed", b, 0644)
}
```
