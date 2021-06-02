package pecoff

import (
	"bytes"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/pkg/errors"
)

func GetSignatures(pefile []byte) ([]*signature.WINCertificate, error) {
	var signatures []*signature.WINCertificate

	sigbuf, err := GetSignatureBytesFromFile(pefile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch signatures slice")
	}

	reader := bytes.NewReader(sigbuf)
	for reader.Len() > signature.SizeofWINCertificate {
		sig, err := signature.ReadWinCertificate(reader)
		if err != nil {
			return []*signature.WINCertificate{}, errors.Wrap(err, "")
		}
		signatures = append(signatures, &sig)

		// All wCerts are padded up to 8 bytes
		// this figures out the padding and removes the bytes
		// so we don't parse them.
		_, size := PaddingBytes(int(sig.Length), 8)
		reader.Read(make([]byte, size))
	}

	return signatures, nil
}
