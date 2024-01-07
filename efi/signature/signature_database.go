package signature

import (
	"bytes"
	"io"
	"reflect"

	"github.com/foxboron/go-uefi/efi/util"
	"github.com/pkg/errors"
)

// SignatureDatabase is a list of EFI signature lists
type SignatureDatabase []*SignatureList

var ErrNotFoundSigList = errors.New("signature list not found")

func NewSignatureDatabase() *SignatureDatabase {
	return &SignatureDatabase{}
}

// Checks if all signatures in a list is present in the signature database
func (sd *SignatureDatabase) SigDataExists(certtype util.EFIGUID, sigdata *SignatureData) bool {
	for _, sdsiglist := range *sd {
		if ok, _ := sdsiglist.Exists(sigdata); ok {
			return true
		}
	}
	return false
}

// Checks if all signatures in a list is present in the signature database
func (sd *SignatureDatabase) Exists(certtype util.EFIGUID, siglist *SignatureList) bool {
	for _, sdsiglist := range *sd {
		if !sdsiglist.CmpHeader(siglist) {
			continue
		}
		return sdsiglist.ExistsInList(siglist)
	}
	return false
}

// Appends the raw signature values to the database
func (sd *SignatureDatabase) Append(certtype util.EFIGUID, owner util.EFIGUID, data []byte) error {
	if _, ok := ValidEFISignatureSchemes[certtype]; !ok {
		return ErrNoSuchSignatureScheme
	}
	for _, l := range *sd {
		if !util.CmpEFIGUID(l.SignatureType, certtype) {
			continue
		}
		size := uint32(len(data)) + util.SizeofEFIGUID
		if size != l.Size {
			continue
		}
		if err := l.AppendSignature(SignatureData{Owner: owner, Data: data}); err != nil {
			return err
		}
		return nil
	}
	sl := NewSignatureList(certtype)
	if err := sl.AppendBytes(owner, data); err != nil {
		return err
	}
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

// Appends a signature database
func (sd *SignatureDatabase) AppendDatabase(s *SignatureDatabase) {
	for _, list := range *s {
		sd.AppendList(list)
	}
}

// Remove the raw signature values to the database
func (sd *SignatureDatabase) Remove(certtype util.EFIGUID, owner util.EFIGUID, data []byte) error {
	// We might want to differentiate between not finding a list for the type and
	// not finding appropriate sigdata in the different lists.
	nosigdata := false
	for _, l := range *sd {
		if !util.CmpEFIGUID(l.SignatureType, certtype) {
			continue
		}
		size := uint32(len(data)) + util.SizeofEFIGUID
		if size != l.Size {
			continue
		}
		if err := l.RemoveBytes(owner, data); errors.Is(err, ErrNotFoundSigData) {
			nosigdata = true
			continue
		}
		if len(l.Signatures) == 0 {
			return sd.RemoveList(l)
		}
		return nil
	}
	if nosigdata {
		return ErrNotFoundSigData
	}
	return ErrNotFoundSigList
}

// Removes a signaure to the database. It will scan available lists for something to remove
func (sd *SignatureDatabase) RemoveSignature(certtype util.EFIGUID, sl *SignatureData) error {
	return sd.Remove(certtype, sl.Owner, sl.Data)
}

func (sd *SignatureDatabase) removeslice(index int) {
	if len(*sd) == 1 {
		*sd = SignatureDatabase{}
		return
	}
	*sd = append((*sd)[:index], (*sd)[index+1:]...)
}

// Removes a signature list from the database
func (sd *SignatureDatabase) RemoveList(sl *SignatureList) error {
	for index, siglist := range *sd {
		if reflect.DeepEqual(sl, siglist) {
			sd.removeslice(index)
			return nil
		}
	}
	return ErrNotFoundSigList
}

// Serialize the Signature Database into bytes
func (sd *SignatureDatabase) Bytes() []byte {
	buf := new(bytes.Buffer)
	WriteSignatureDatabase(buf, *sd)
	return buf.Bytes()
}

func (sd *SignatureDatabase) Marshal(b *bytes.Buffer) {
	WriteSignatureDatabase(b, *sd)
}

func (sd *SignatureDatabase) Unmarshal(b *bytes.Buffer) error {
	s, err := ReadSignatureDatabase(b)
	if err != nil {
		return err
	}
	*sd = s
	return nil
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
