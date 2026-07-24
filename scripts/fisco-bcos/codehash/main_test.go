package main

import (
	"encoding/hex"
	"testing"

	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/sha3"
)

func TestNativeEmptyCodeHashVectors(t *testing.T) {
	keccak := sha3.NewLegacyKeccak256()
	if got := hex.EncodeToString(keccak.Sum(nil)); got != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
		t.Fatalf("Keccak-256 empty vector = %s", got)
	}
	sm3Sum := sm3.Sum(nil)
	if got := hex.EncodeToString(sm3Sum[:]); got != "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b" {
		t.Fatalf("SM3 empty vector = %s", got)
	}
}
