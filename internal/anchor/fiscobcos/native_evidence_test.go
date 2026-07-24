package fiscobcos

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestNativeReceiptHashableGoldenVector(t *testing.T) {
	t.Parallel()
	// Fixture derived from TransactionReceipt.tars at upstream
	// bcos-tars-protocol commit 78d25fc (ReceiptData tags 1..7 and LogEntry
	// tags 1..3), encoded with the TarsGo reference codec.
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
	const wantPreimage = "1c260435323038360530786162634c5d000002dead6900010a1604307830312900010d00002011111111111111111111111111111111111111111111111111111111111111113d000002aabb0b702a"
	if got := hex.EncodeToString(preimage); got != wantPreimage {
		t.Fatalf("receipt preimage=%s", got)
	}
	if len(logs) != 1 || hex.EncodeToString(logs[0]) != "0a1604307830312900010d00002011111111111111111111111111111111111111111111111111111111111111113d000002aabb0b" {
		t.Fatalf("canonical logs=%x", logs)
	}
	for _, test := range []struct {
		algorithm string
		want      string
	}{
		{algorithm: HashKeccak256, want: "9091ac83801d140f928fce3d396b6afddb1284c7d1f16c9c9d85aed814ac9796"},
		{algorithm: "sm3", want: "e050dbeda9a5031686a72790b9acea6269435e10deeece348079fdf242c34cc2"},
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
	// Fixture derived from Block.tars at upstream bcos-tars-protocol commit
	// 78d25fc (BlockHeaderData tags 2..13), encoded with TarsGo.
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
	const wantPreimage = "2c3900010a10012d00002001010101010101010101010101010101010101010101010101010101010101010b4d00002002020202020202020202020202020202020202020202020202020202020202025d00002003030303030303030303030303030303030303030303030303030303030303036d00002004040404040404040404040404040404040404040404040404040404040404047002860239399003a001b900020d0000066e6f64652d610d0000066e6f64652d62cd000002aabbd9000200040005"
	if got := hex.EncodeToString(preimage); got != wantPreimage {
		t.Fatalf("block preimage=%s", got)
	}
	for _, test := range []struct {
		algorithm string
		want      string
	}{
		{algorithm: HashKeccak256, want: "a9a081aa291b28fa8735a153e3386269969e943205fd9dd9829f31c14e8b46f9"},
		{algorithm: "sm3", want: "bba2ed9da8345cfe7a0e8be6ec2a946748769a6ceca441773ba5975d756a8b7e"},
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

func TestNativeReceiptVersionUsesOfficialSchemaWithoutInventedFields(t *testing.T) {
	t.Parallel()
	if _, _, err := MarshalNativeReceiptPreimage(NativeReceiptFields{Version: 1}); err != nil {
		t.Fatalf("official ReceiptData schema fields were rejected: %v", err)
	}
}
