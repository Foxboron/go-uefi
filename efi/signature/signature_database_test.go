package signature

import (
	"fmt"
	"testing"
)

func TestSigdatabase(t *testing.T) {
	sigdb := SignatureDatabase{}
	for _, sig := range sigdata {
		sigdb.AppendSignature(CERT_SHA256_GUID, &sig)
	}
	if sigdb[0].ListSize != 172 {
		fmt.Println(sigdb[0].ListSize)
		t.Fatal("list size incorrect")
	}
	if sigdb[0].Size != 48 {
		fmt.Println(sigdb[0].ListSize)
		t.Fatal("size incorrect")
	}
	if len(sigdb[0].Signatures) != 3 {
		t.Fatal("number of signatures wrong")
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
