package signature

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/pkg/errors"
)

func TestSigdatabaseAppend(t *testing.T) {
	sigdb := SignatureDatabase{}
	for _, sig := range sigdata {
		sigdb.AppendSignature(CERT_SHA256_GUID, &sig)
	}
	if sigdb[0].ListSize != 172 {
		fmt.Println(sigdb[0].ListSize)
		t.Fatal("append: list size incorrect")
	}
	if sigdb[0].Size != 48 {
		fmt.Println(sigdb[0].ListSize)
		t.Fatal("append: size incorrect")
	}
	if len(sigdb[0].Signatures) != 3 {
		t.Fatal("append: number of signatures wrong")
	}
}

func TestSigdatabaseAppendSame(t *testing.T) {
	sigdb := SignatureDatabase{}
	for _, sig := range sigdata {
		sigdb.AppendSignature(CERT_SHA256_GUID, &sig)
	}
	sigdb.AppendSignature(CERT_SHA256_GUID, &sigdata[0])
	if len(sigdb[0].Signatures) != 3 {
		t.Fatal("append: number of signatures wrong")
	}
}

func TestSigdatabaseRemove(t *testing.T) {
	sigdb := SignatureDatabase{}
	for _, sig := range sigdata {
		sigdb.AppendSignature(CERT_SHA256_GUID, &sig)
	}
	err := sigdb.RemoveSignature(CERT_SHA256_GUID, &sigdata[0])
	if err != nil {
		t.Error(err)
	}
	if sigdb[0].ListSize != 124 {
		fmt.Println(sigdb[0].ListSize)
		t.Fatal("remove: list size incorrect")
	}
	if sigdb[0].Size != 48 {
		fmt.Println(sigdb[0].ListSize)
		t.Fatal("remove: size incorrect")
	}
	if len(sigdb[0].Signatures) != 2 {
		t.Fatal("remove: number of signatures wrong")
	}
}

func TestSigdatabaseRemoveSame(t *testing.T) {
	sigdb := SignatureDatabase{}
	for _, sig := range sigdata {
		sigdb.AppendSignature(CERT_SHA256_GUID, &sig)
	}
	sigdb.RemoveSignature(CERT_SHA256_GUID, &sigdata[0])
	err := sigdb.RemoveSignature(CERT_SHA256_GUID, &sigdata[0])
	if !errors.Is(err, ErrNotFoundSigData) {
		t.Fatalf("remove: wrong error, got: %s", err)
	}
}

func TestSigdatabaseRemoveWrongSiglistType(t *testing.T) {
	sigdb := SignatureDatabase{}
	for _, sig := range sigdata {
		sigdb.AppendSignature(CERT_SHA256_GUID, &sig)
	}
	err := sigdb.RemoveSignature(CERT_X509_GUID, &sigdata[0])
	if !errors.Is(err, ErrNotFoundSigList) {
		t.Fatalf("remove: wrong error, got: %s", err)
	}
}

func TestSigdatabaseRemoveAll(t *testing.T) {
	var err error
	sigdb := SignatureDatabase{}
	for _, sig := range sigdata {
		sigdb.AppendSignature(CERT_SHA256_GUID, &sig)
	}
	for index, sig := range sigdata {
		err = sigdb.RemoveSignature(CERT_SHA256_GUID, &sig)
		if len(sigdb) != 0 && 3-(index+1) != len(sigdb[0].Signatures) {
			t.Fatalf("remove all: sigdb wrong size. expected %d, got %d", 3-(index+1), len(sigdb[0].Signatures))
		}
	}
	if err != nil {
		t.Fatalf("remove all: got error: %s", err)
	}
	if !reflect.DeepEqual(sigdb, SignatureDatabase{}) {
		t.Fatalf("remove all: not empty interface")
	}
}

func TestSigdatabaseExists(t *testing.T) {
	sigdb := SignatureDatabase{}
	for _, sig := range sigdata {
		sigdb.AppendSignature(CERT_SHA256_GUID, &sig)
	}
	sl := NewSignatureList(CERT_SHA256_GUID)
	for _, sig := range sigdata {
		sl.AppendBytes(sig.Owner, sig.Data)
	}
	if !sigdb.Exists(CERT_SHA256_GUID, sl) {
		t.Fatalf("exists: siglist is not in database")
	}
}

func TestSigdatabaseSigdataExists(t *testing.T) {
	sigdb := SignatureDatabase{}
	for _, sig := range sigdata {
		sigdb.AppendSignature(CERT_SHA256_GUID, &sig)
	}
	if !sigdb.SigDataExists(CERT_SHA256_GUID, &sigdata[0]) {
		t.Fatalf("exists: siglist is not in database")
	}
}
