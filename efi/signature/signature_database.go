package signature

import (
	"io"

	"github.com/foxboron/go-uefi/efi/util"
	"github.com/pkg/errors"
)

// SignatureDatabase is a list of EFI signature lists
type SignatureDatabase []*SignatureList

// Appends the raw signature values to the database
func (sd *SignatureDatabase) Append(certtype util.EFIGUID, owner util.EFIGUID, data []byte) error {
	for _, l := range *sd {
		if !util.CmpEFIGUID(l.SignatureType, certtype) {
			continue
		}
		size := uint32(len(data)) + util.SizeofEFIGUID
		if size != l.Size {
			continue
		}
		l.AppendSignature(SignatureData{Owner: owner, Data: data})
		return nil
	}
	sl := NewSignatureList(certtype)
	sl.AppendBytes(owner, data)
	*sd = append(*sd, sl)
	return nil
}

// Appends a signaure to the database. It will scan the database for the appropriate list to append
// itself to.
func (sd *SignatureDatabase) AppendSignature(certtype util.EFIGUID, sl *SignatureData) error {
	return sd.Append(certtype, sl.Owner, sl.Data)
}

// Appends a signature list to the database
// TODO: Should merge towards a fitting list?
func (sd *SignatureDatabase) AppendList(sl *SignatureList) {
	*sd = append(*sd, sl)
}

// Write a signature database which contains a slice of SignautureLists
func WriteSignatureDatabase(b io.Writer, sigdb SignatureDatabase) {
	for _, l := range sigdb {
		WriteSignatureList(b, *l)
	}
}

// Reads several signature lists from a io.Reader. It assumes io.EOF means there
// are no more signatures to read as opposed to an actual issue
func ReadSignatureDatabase(f io.Reader) (SignatureDatabase, error) {
	siglist := []*SignatureList{}
	for {
		sig, err := ReadSignatureList(f)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return siglist, errors.Wrapf(err, "failed to parse signature lists")
		}
		siglist = append(siglist, sig)
	}
	return siglist, nil
}
