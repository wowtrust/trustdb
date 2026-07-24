package fiscobcos

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestTrustDBAnchorV1CallEncoding(t *testing.T) {
	payload, err := NewAnchorPayload("INTL_V1", testSTH("INTL_V1"))
	if err != nil {
		t.Fatal(err)
	}
	call, err := PublishCallData(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(call) != 4+6*32 {
		t.Fatalf("publish calldata length=%d", len(call))
	}
	if !bytes.Equal(call[:4], abiSelector(publishSignature)) ||
		!bytes.Equal(call[4:36], payload.AnchorID) ||
		!bytes.Equal(call[36:68], payload.StreamID) ||
		!bytes.Equal(call[4+3*32:4+4*32], payload.RootHash) ||
		!bytes.Equal(call[4+4*32:4+5*32], payload.SignedSTHDigest) {
		t.Fatal("publish calldata does not preserve exact payload fields")
	}
	getter, err := GetAnchorCallData(payload.AnchorID)
	if err != nil {
		t.Fatal(err)
	}
	if len(getter) != 36 || !bytes.Equal(getter[:4], abiSelector(getAnchorSignature)) || !bytes.Equal(getter[4:], payload.AnchorID) {
		t.Fatal("getAnchor calldata mismatch")
	}
}

func TestDecodeAnchorRecordRejectsNonCanonicalABI(t *testing.T) {
	// This is the exact 7-word ABI result returned by TrustDBAnchorV1 for an
	// unknown anchor ID: Solidity zero-initializes every tuple element,
	// including exists=false.
	absentVector, err := hex.DecodeString(strings.Repeat("00", 7*32))
	if err != nil {
		t.Fatal(err)
	}
	absent, err := DecodeAnchorRecord(absentVector)
	if err != nil || absent.Exists || len(absent.StreamID) != 0 {
		t.Fatalf("absent record=%+v err=%v", absent, err)
	}
	nonCanonicalAbsent := append([]byte(nil), absentVector...)
	nonCanonicalAbsent[0] = 1
	if _, err := DecodeAnchorRecord(nonCanonicalAbsent); err == nil {
		t.Fatal("decoder accepted a non-zero tuple with exists=false")
	}
	data := make([]byte, 7*32)
	copy(data[:32], bytes.Repeat([]byte{1}, 32))
	data[2*32-1] = 7
	copy(data[2*32:3*32], bytes.Repeat([]byte{2}, 32))
	copy(data[3*32:4*32], bytes.Repeat([]byte{3}, 32))
	copy(data[4*32+12:5*32], bytes.Repeat([]byte{4}, 20))
	data[6*32-1] = 1
	data[7*32-1] = 1

	record, err := DecodeAnchorRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	if record.TreeSize != 7 || record.PayloadVersion != 1 || !record.Exists || len(record.Publisher) != 20 {
		t.Fatalf("record=%+v", record)
	}

	for _, mutate := range []func([]byte){
		func(in []byte) { in[32] = 1 },
		func(in []byte) { in[4*32] = 1 },
		func(in []byte) { in[5*32] = 1 },
		func(in []byte) { in[6*32+31] = 2 },
	} {
		candidate := append([]byte(nil), data...)
		mutate(candidate)
		if _, err := DecodeAnchorRecord(candidate); err == nil {
			t.Fatal("decoder accepted non-canonical ABI response")
		}
	}
	if _, err := DecodeAnchorRecord(data[:len(data)-1]); err == nil {
		t.Fatal("decoder accepted truncated ABI response")
	}
}
