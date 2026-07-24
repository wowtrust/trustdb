package main

import (
	"testing"

	"github.com/FISCO-BCOS/go-sdk/v3/types"
)

func TestPerformanceRunBindingGolden(t *testing.T) {
	t.Parallel()
	input := smokePerformanceEvidence{
		WarmupCount: 0,
		SampleCount: 1,
		TimingSamples: []smokePerformanceTimingSample{{
			PrepareSignEncodeNS:         1,
			SubmitToReceiptNS:           2,
			ReceiptProofRetrievalNS:     3,
			TransactionProofRetrievalNS: 4,
			BlockRetrievalNS:            5,
		}},
		VerificationSamples: []verificationSample{{
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
}
