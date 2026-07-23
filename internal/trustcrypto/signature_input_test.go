package trustcrypto

import (
	"bytes"
	"testing"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
)

func TestSignatureInputForSuitePinsFraming(t *testing.T) {
	t.Parallel()

	payload := []byte{0xa1, 0x01, 0x02}
	intl, err := SignatureInputForSuite(cryptosuite.INTLV1, SignaturePurposeClientClaim, payload)
	if err != nil {
		t.Fatal(err)
	}
	wantINTL := append([]byte("trustdb.client-claim.v1\x00"), payload...)
	if !bytes.Equal(intl, wantINTL) {
		t.Fatalf("INTL_V1 input = %x, want %x", intl, wantINTL)
	}
	cn, err := SignatureInputForSuite(cryptosuite.CNSMV1, SignaturePurposeClientClaim, payload)
	if err != nil {
		t.Fatal(err)
	}
	wantCN := append([]byte("trustdb.client-claim.v2\x00CN_SM_V1\x00"), payload...)
	if !bytes.Equal(cn, wantCN) {
		t.Fatalf("CN_SM_V1 input = %x, want %x", cn, wantCN)
	}
	if bytes.Equal(intl, cn) {
		t.Fatal("suite signature inputs are identical")
	}
}

func TestCNSMSignaturePurposesUseRegisteredDomains(t *testing.T) {
	t.Parallel()

	tests := map[SignaturePurpose]string{
		SignaturePurposeClientClaim:      "trustdb.client-claim.v2",
		SignaturePurposeAcceptedReceipt:  "trustdb.accepted-receipt.v2",
		SignaturePurposeCommittedReceipt: "trustdb.committed-receipt.v2",
		SignaturePurposeKeyEvent:         "trustdb.key-event.v2",
		SignaturePurposeSignedTreeHead:   "trustdb.signed-tree-head.v2",
	}
	for purpose, domain := range tests {
		got, err := SignatureInputForSuite(cryptosuite.CNSMV1, purpose, []byte("payload"))
		if err != nil {
			t.Fatalf("SignatureInputForSuite(%s) error = %v", purpose, err)
		}
		want := []byte(domain + "\x00CN_SM_V1\x00payload")
		if !bytes.Equal(got, want) {
			t.Fatalf("SignatureInputForSuite(%s) = %x, want %x", purpose, got, want)
		}
	}
}

func TestSignatureInputForSuiteRejectsUnknownPurposeAndSuite(t *testing.T) {
	t.Parallel()

	if _, err := SignatureInputForSuite(cryptosuite.ID("UNKNOWN"), SignaturePurposeClientClaim, nil); err == nil {
		t.Fatal("unknown suite error = nil")
	}
	if _, err := SignatureInputForSuite(cryptosuite.CNSMV1, SignaturePurpose("unknown"), nil); err == nil {
		t.Fatal("unknown signature purpose error = nil")
	}
}

func TestAppendSignatureInputForSuitePreservesPrefix(t *testing.T) {
	t.Parallel()

	got, err := AppendSignatureInputForSuite([]byte("prefix:"), cryptosuite.CNSMV1, SignaturePurposeSignedTreeHead, []byte("sth"))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("prefix:trustdb.signed-tree-head.v2\x00CN_SM_V1\x00sth")
	if !bytes.Equal(got, want) {
		t.Fatalf("AppendSignatureInputForSuite() = %x, want %x", got, want)
	}
}
