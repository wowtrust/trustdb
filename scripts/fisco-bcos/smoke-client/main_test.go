package main

import (
	"encoding/hex"
	"testing"

	"github.com/FISCO-BCOS/go-sdk/v3/abi"
	"github.com/FISCO-BCOS/go-sdk/v3/types"
)

func TestPerformanceDigestSequence(t *testing.T) {
	t.Parallel()
	const expectedFirst = "b8f72afd867de7595dca41f2a87f93d76a25ae6263f21c7a0cc694415e89c197"
	first := performanceDigest(0)
	if hex.EncodeToString(first[:]) != expectedFirst {
		t.Fatalf("unexpected first deterministic digest: %x", first)
	}
	second := performanceDigest(1)
	if first == second {
		t.Fatal("successive performance calls reused a digest")
	}
	if performanceDigest(0) != first {
		t.Fatal("performance digest sequence is not deterministic")
	}
}

func TestRawPerformanceInputsAreUniqueAndBounded(t *testing.T) {
	t.Parallel()
	var parsed abi.ABI
	seen := make(map[byte]struct{}, 120)
	for index := 0; index < 120; index++ {
		input, err := performanceCallInput(parsed, true, index)
		if err != nil {
			t.Fatalf("performanceCallInput(%d): %v", index, err)
		}
		if len(input) != 1 {
			t.Fatalf("performanceCallInput(%d) length = %d, want 1", index, len(input))
		}
		if _, duplicate := seen[input[0]]; duplicate {
			t.Fatalf("performanceCallInput(%d) reused byte %d", index, input[0])
		}
		seen[input[0]] = struct{}{}
	}
	if _, err := performanceCallInput(parsed, true, 256); err == nil {
		t.Fatal("performanceCallInput accepted an out-of-domain sample")
	}
}

func TestPerformanceRunBindingGolden(t *testing.T) {
	t.Parallel()
	input := performanceEvidence{
		WarmupCount: 0,
		SampleCount: 1,
		TimingSamples: []performanceTimingSample{{
			PrepareSignEncodeNS:         1,
			SubmitToReceiptNS:           2,
			ReceiptProofRetrievalNS:     3,
			TransactionProofRetrievalNS: 4,
			BlockRetrievalNS:            5,
		}},
		VerificationSamples: []performanceVerificationSample{{
			Receipt: &types.Receipt{TransactionHash: "0xAbC"},
			Block:   &types.Block{Hash: "0xDeF"},
		}},
	}
	binding, err := performanceRunBinding("guomi", input)
	if err != nil {
		t.Fatalf("performanceRunBinding: %v", err)
	}
	const expected = "0829e6ca837709a449cc1f4c305ac32a9d2107fe406869ee03d4e1fa80353e9e"
	if binding != expected {
		t.Fatalf("binding = %s, want %s", binding, expected)
	}
	input.TimingSamples[0].BlockRetrievalNS++
	changed, err := performanceRunBinding("guomi", input)
	if err != nil {
		t.Fatalf("performanceRunBinding after timing change: %v", err)
	}
	if changed == binding {
		t.Fatal("run binding did not cover network timings")
	}
}
