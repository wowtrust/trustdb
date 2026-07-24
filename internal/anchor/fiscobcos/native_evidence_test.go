package fiscobcos

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/TarsCloud/TarsGo/tars/protocol/codec"
)

func TestNativeReceiptHashableGoldenVector(t *testing.T) {
	t.Parallel()
	// Fixture derived from the exact v3.16.3 TarsHashable.h field projection.
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
	// Fixture derived from the exact v3.16.3 TarsHashable.h field projection.
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

func TestNativeReceiptPinnedV3163LiveCaptureRejectsWriteToPreimage(t *testing.T) {
	t.Parallel()
	fields := NativeReceiptFields{
		Version:     0,
		GasUsed:     "99046",
		Status:      0,
		BlockNumber: 2,
		Logs: []NativeLogFields{
			{
				Address: "6849f21d1e455e9f0712b1e99fa4fcd23758e8f1",
				Topics: [][]byte{
					mustEvidenceHex(t, "be07528b0b055cb8ba3e88331e102adc06f43de4c6cbe0ac74c51e01ecc43def"),
					mustEvidenceHex(t, "747275737464622d666973636f2d636f6d7061746962696c6974792d70726f62"),
					mustEvidenceHex(t, "917e5b56d8566402571e8152e753aaa8f07f37c70f019ad3d97841a6a1b040d5"),
					mustEvidenceHex(t, "000000000000000000000000cdecc61232fc56b4f0b5f45523fc5a042e73d4ac"),
				},
				Data: mustEvidenceHex(t,
					"0000000000000000000000000000000000000000000000000000000000000001"+
						"994305566f2628e97309e68b846c4648d46fe6278091603a541659479053fd74"+
						"747275737464622d666973636f2d636f6d7061746962696c6974792d70726f6200"+
						"00000000000000000000000000000000000000000000000000000000000001"),
			},
			{
				Address: "6849f21d1e455e9f0712b1e99fa4fcd23758e8f1",
				Topics: [][]byte{
					mustEvidenceHex(t, "c8f7565859107929ba4b285bfb17dfba069f69ab64447f49d6fecb70f6bd552b"),
					mustEvidenceHex(t, "747275737464622d666973636f2d636f6d7061746962696c6974792d70726f62"),
				},
			},
		},
	}
	consensusPreimage, _, err := MarshalNativeReceiptPreimage(fields)
	if err != nil {
		t.Fatal(err)
	}
	consensusHash, err := HashNativeEvidence(HashKeccak256, consensusPreimage)
	if err != nil {
		t.Fatal(err)
	}
	const nodeReceiptHash = "d1cf4c5f089300233681631a2d8a454ab0f719bc877ea74ed788076dda96cbda"
	if hex.EncodeToString(consensusHash) != nodeReceiptHash {
		t.Fatalf("v3.16.3 live receipt hash=%x", consensusHash)
	}

	writeToPreimage := marshalTARSReceiptForRegression(t, fields)
	if bytes.Equal(consensusPreimage, writeToPreimage) {
		t.Fatal("v3.16.3 consensus projection collapsed to later writeTo serialization")
	}
	writeToHash, err := HashNativeEvidence(HashKeccak256, writeToPreimage)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(writeToHash, consensusHash) {
		t.Fatal("distinct v3.16.3 and writeTo preimages unexpectedly produced the same hash")
	}
}

func marshalTARSReceiptForRegression(t *testing.T, fields NativeReceiptFields) []byte {
	t.Helper()
	out := codec.NewBuffer()
	mustTARSEncode(t, out.WriteInt32(fields.Version, 1))
	mustTARSEncode(t, out.WriteString(fields.GasUsed, 2))
	mustTARSEncode(t, out.WriteInt32(fields.Status, 4))
	mustTARSEncode(t, out.WriteHead(codec.LIST, 6))
	mustTARSEncode(t, out.WriteInt32(int32(len(fields.Logs)), 0))
	for _, log := range fields.Logs {
		mustTARSEncode(t, out.WriteHead(codec.StructBegin, 0))
		mustTARSEncode(t, out.WriteString(log.Address, 1))
		mustTARSEncode(t, out.WriteHead(codec.LIST, 2))
		mustTARSEncode(t, out.WriteInt32(int32(len(log.Topics)), 0))
		for _, topic := range log.Topics {
			writeTARSBytesForRegression(t, out, topic, 0)
		}
		if len(log.Data) != 0 {
			writeTARSBytesForRegression(t, out, log.Data, 3)
		}
		mustTARSEncode(t, out.WriteHead(codec.StructEnd, 0))
	}
	mustTARSEncode(t, out.WriteInt64(fields.BlockNumber, 7))
	return append([]byte(nil), out.ToBytes()...)
}

func writeTARSBytesForRegression(t *testing.T, out *codec.Buffer, value []byte, tag byte) {
	t.Helper()
	mustTARSEncode(t, out.WriteHead(codec.SimpleList, tag))
	mustTARSEncode(t, out.WriteHead(codec.BYTE, 0))
	mustTARSEncode(t, out.WriteInt32(int32(len(value)), 0))
	mustTARSEncode(t, out.WriteSliceUint8(value))
}

func mustTARSEncode(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustEvidenceHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
