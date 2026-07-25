package types

import (
	"bytes"
	"testing"

	"github.com/TarsCloud/TarsGo/tars/protocol/codec"
	"github.com/ethereum/go-ethereum/common"
)

func TestTrustDBTransactionRoundTripOmitsAbsentSender(t *testing.T) {
	t.Parallel()

	contract := common.BytesToAddress(bytes.Repeat([]byte{0x42}, 20))
	original := NewTransaction(
		contract,
		nil,
		0,
		nil,
		9000,
		[]byte{1, 2, 3, 4},
		"trustdb-absent-sender",
		"chain0",
		"group0",
		"",
		false,
	)
	original.Signature = bytes.Repeat([]byte{0x51}, 65)
	if original.Sender != nil {
		t.Fatal("fixture unexpectedly carries a sender")
	}
	encoded := original.Bytes()

	var decoded Transaction
	if err := decoded.ReadFrom(codec.NewReader(encoded)); err != nil {
		t.Fatalf("decode transaction: %v", err)
	}
	if decoded.Sender != nil {
		t.Fatal("decoder invented an absent sender")
	}
	if roundTrip := decoded.Bytes(); !bytes.Equal(roundTrip, encoded) {
		t.Fatalf("round-trip encoding changed: got %x want %x", roundTrip, encoded)
	}
}
