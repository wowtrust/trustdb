package fiscobcos

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestNativeReceiptHashableGoldenVector(t *testing.T) {
	t.Parallel()
	preimage, logs, err := MarshalNativeReceiptPreimage(NativeReceiptFields{
		Version:         0,
		GasUsed:         "5208",
		ContractAddress: "0xabc",
		Status:          0,
		Output:          []byte{0xde, 0xad},
		Logs: []NativeLogFields{{
			Address: "0x01",
			Topics:  [][]byte{bytes.Repeat([]byte{0x11}, 32)},
			Data:    []byte{0xaa, 0xbb},
		}},
		BlockNumber: 42,
	})
	if err != nil {
		t.Fatal(err)
	}
	const wantPreimage = "0000000035323038307861626300000000dead307830311111111111111111111111111111111111111111111111111111111111111111aabb000000000000002a"
	if got := hex.EncodeToString(preimage); got != wantPreimage {
		t.Fatalf("receipt preimage=%s", got)
	}
	if len(logs) != 1 || hex.EncodeToString(logs[0]) != "307830311111111111111111111111111111111111111111111111111111111111111111aabb" {
		t.Fatalf("canonical logs=%x", logs)
	}
	for _, test := range []struct {
		algorithm string
		want      string
	}{
		{algorithm: HashKeccak256, want: "3e0fb831003186acc2860e72e122fe2727dab4f4324571efbf83eece05239c89"},
		{algorithm: "sm3", want: "6556f97f1a4e40eefa063b8f9c2e2d2c5588407f01937215973938e2b1ebb697"},
	} {
		got, err := HashNativeEvidence(test.algorithm, preimage)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != test.want {
			t.Fatalf("%s receipt hash=%x", test.algorithm, got)
		}
	}
}

func TestNativeBlockHeaderHashableGoldenVector(t *testing.T) {
	t.Parallel()
	preimage, err := MarshalNativeBlockHeaderPreimage(NativeBlockHeaderFields{
		Version:          0,
		ParentInfo:       []NativeParentInfo{{BlockNumber: 1, BlockHash: bytes.Repeat([]byte{0x01}, 32)}},
		TransactionsRoot: bytes.Repeat([]byte{0x02}, 32),
		ReceiptsRoot:     bytes.Repeat([]byte{0x03}, 32),
		StateRoot:        bytes.Repeat([]byte{0x04}, 32),
		BlockNumber:      2,
		GasUsed:          "99",
		Timestamp:        3,
		Sealer:           1,
		SealerList:       [][]byte{[]byte("node-a"), []byte("node-b")},
		ExtraData:        []byte{0xaa, 0xbb},
		ConsensusWeights: []int64{4, 5},
	})
	if err != nil {
		t.Fatal(err)
	}
	const wantPreimage = "000000000000000000000001010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040400000000000000023939000000000000000300000000000000016e6f64652d616e6f64652d62aabb00000000000000040000000000000005"
	if got := hex.EncodeToString(preimage); got != wantPreimage {
		t.Fatalf("block preimage=%s", got)
	}
	for _, test := range []struct {
		algorithm string
		want      string
	}{
		{algorithm: HashKeccak256, want: "feee42e98056156d491eb990e2303a5cb3c236bd02040eaad653b806d6801780"},
		{algorithm: "sm3", want: "4432f60cceee9159178d7e809d3373a77ed9fc9d2987b5958f1d726d9aaaf017"},
	} {
		got, err := HashNativeEvidence(test.algorithm, preimage)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != test.want {
			t.Fatalf("%s block hash=%x", test.algorithm, got)
		}
	}
}

func TestNativeReceiptV1FailsClosedWithoutEffectiveGasPrice(t *testing.T) {
	t.Parallel()
	if _, _, err := MarshalNativeReceiptPreimage(NativeReceiptFields{Version: 1}); err == nil {
		t.Fatal("receipt v1 without effectiveGasPrice was accepted")
	}
}
