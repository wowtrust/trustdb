package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FISCO-BCOS/go-sdk/v3/abi"
	"github.com/FISCO-BCOS/go-sdk/v3/types"
	"github.com/ethereum/go-ethereum/common"
)

func TestPerformanceDigestSequence(t *testing.T) {
	t.Parallel()
	const expectedFirst = "6a87537eee5ad5958dd9ce306346f58e8ad8efcc388e68b3921382962ca40342"
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

func TestProductionPublishInputsAndEventAreModeBound(t *testing.T) {
	t.Parallel()

	standard := testProductionAnchorABI(t, false)
	guomi := testProductionAnchorABI(t, true)
	standardInput, err := performanceCallInput(standard, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	guomiInput, err := performanceCallInput(guomi, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(standardInput) != 4+6*32 || len(guomiInput) != len(standardInput) {
		t.Fatalf("publish calldata lengths = %d/%d", len(standardInput), len(guomiInput))
	}
	if string(standardInput[:4]) == string(guomiInput[:4]) {
		t.Fatal("standard and Guomi publish selectors are identical")
	}
	if string(standardInput[4:]) != string(guomiInput[4:]) {
		t.Fatal("standard and Guomi publish arguments are not the same opaque payload")
	}

	payload := functionalAnchorPayload()
	publisher := common.HexToAddress("0x1234567890123456789012345678901234567890")
	eventDefinition := guomi.Events["AnchorPublished"]
	data, err := eventDefinition.Inputs.NonIndexed().Pack(
		payload.TreeSize,
		payload.RootHash,
		payload.SignedSTHDigest,
		payload.PayloadVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	event := types.Log{
		Topics: []common.Hash{
			eventDefinition.ID(),
			common.BytesToHash(payload.AnchorID[:]),
			common.BytesToHash(payload.StreamID[:]),
			common.BytesToHash(publisher.Bytes()),
		},
		Data: data,
	}
	if err := verifyAnchorPublishedEvent(guomi, event, payload, publisher); err != nil {
		t.Fatalf("verify Guomi AnchorPublished: %v", err)
	}
	event.Data[len(event.Data)-1] ^= 1
	if err := verifyAnchorPublishedEvent(guomi, event, payload, publisher); err == nil {
		t.Fatal("AnchorPublished verification accepted tampered payload data")
	}

	record := storedAnchorRecord{
		StreamID:        payload.StreamID,
		TreeSize:        payload.TreeSize,
		RootHash:        payload.RootHash,
		SignedSTHDigest: payload.SignedSTHDigest,
		Publisher:       publisher,
		PayloadVersion:  payload.PayloadVersion,
		Exists:          true,
	}
	output, err := guomi.Methods["getAnchor"].Outputs.Pack(record)
	if err != nil {
		t.Fatal(err)
	}
	var decoded storedAnchorRecord
	if err := guomi.Unpack(&decoded, "getAnchor", output); err != nil {
		t.Fatalf("decode production getAnchor output: %v", err)
	}
	if decoded != record {
		t.Fatalf("decoded getAnchor record = %+v, want %+v", decoded, record)
	}
}

func testProductionAnchorABI(t *testing.T, smCrypto bool) abi.ABI {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(
		"..",
		"..",
		"..",
		"contracts",
		"fisco-bcos",
		"artifacts",
		"standard",
		"TrustDBAnchorV1.abi",
	))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := abi.JSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if smCrypto {
		parsed.SetSMCrypto()
	}
	return parsed
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
