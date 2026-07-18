package prooflevel

import (
	"strings"
	"testing"
)

func TestEvaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   Evidence
		want Level
	}{
		{
			name: "no evidence",
			in:   Evidence{},
			want: Unknown,
		},
		{
			name: "content without client signature is not L1",
			in: Evidence{
				ContentHash: true,
			},
			want: Unknown,
		},
		{
			name: "L1 requires content hash and client signature",
			in: Evidence{
				ContentHash:     true,
				ClientSignature: true,
			},
			want: L1,
		},
		{
			name: "L2 requires accepted receipt",
			in: Evidence{
				ContentHash:     true,
				ClientSignature: true,
				AcceptedReceipt: true,
			},
			want: L2,
		},
		{
			name: "committed receipt without batch proof stays L2",
			in: Evidence{
				ContentHash:      true,
				ClientSignature:  true,
				AcceptedReceipt:  true,
				CommittedReceipt: true,
			},
			want: L2,
		},
		{
			name: "L3 requires committed receipt and batch proof",
			in: Evidence{
				ContentHash:      true,
				ClientSignature:  true,
				AcceptedReceipt:  true,
				CommittedReceipt: true,
				BatchProof:       true,
			},
			want: L3,
		},
		{
			name: "global proof without batch proof does not skip to L4",
			in: Evidence{
				ContentHash:     true,
				ClientSignature: true,
				AcceptedReceipt: true,
				GlobalLogProof:  true,
			},
			want: L2,
		},
		{
			name: "L4 requires global log proof",
			in: Evidence{
				ContentHash:      true,
				ClientSignature:  true,
				AcceptedReceipt:  true,
				CommittedReceipt: true,
				BatchProof:       true,
				GlobalLogProof:   true,
			},
			want: L4,
		},
		{
			name: "anchor without global proof stays L3",
			in: Evidence{
				ContentHash:      true,
				ClientSignature:  true,
				AcceptedReceipt:  true,
				CommittedReceipt: true,
				BatchProof:       true,
				STHAnchorResult:  true,
			},
			want: L3,
		},
		{
			name: "L5 requires global proof and STH anchor result",
			in: Evidence{
				ContentHash:      true,
				ClientSignature:  true,
				AcceptedReceipt:  true,
				CommittedReceipt: true,
				BatchProof:       true,
				GlobalLogProof:   true,
				STHAnchorResult:  true,
			},
			want: L5,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Evaluate(tt.in); got != tt.want {
				t.Fatalf("Evaluate() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRankAndAtLeast(t *testing.T) {
	t.Parallel()

	if Rank(Unknown) != 0 {
		t.Fatalf("Rank(Unknown) = %d, want 0", Rank(Unknown))
	}
	if !AtLeast(L5, L4) {
		t.Fatalf("AtLeast(L5, L4) = false, want true")
	}
	if AtLeast(L3, L4) {
		t.Fatalf("AtLeast(L3, L4) = true, want false")
	}
	if AtLeast(Unknown, L1) {
		t.Fatalf("AtLeast(Unknown, L1) = true, want false")
	}
}

func TestEvidenceForRoundTripsThroughEvaluate(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		level Level
	}{
		{name: "unknown", level: Unknown},
		{name: "L1", level: L1},
		{name: "L2", level: L2},
		{name: "L3", level: L3},
		{name: "L4", level: L4},
		{name: "L5", level: L5},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Evaluate(EvidenceFor(tt.level)); got != tt.level {
				t.Fatalf("Evaluate(EvidenceFor(%s)) = %s, want %s", tt.level, got, tt.level)
			}
		})
	}
}

func TestDefinitionsReturnsCopy(t *testing.T) {
	t.Parallel()

	defs := Definitions()
	if len(defs) != 5 {
		t.Fatalf("Definitions len = %d, want 5", len(defs))
	}
	defs[0].Level = L5
	if Definitions()[0].Level != L1 {
		t.Fatalf("Definitions returned mutable package state")
	}
}

func TestParse(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"L1", "L2", "L3", "L4", "L5", " l5 "} {
		got, ok := Parse(raw)
		want := strings.ToUpper(strings.TrimSpace(raw))
		if !ok || got.String() != want {
			t.Fatalf("Parse(%q) = %q, %v, want %q true", raw, got, ok, want)
		}
	}
	if got, ok := Parse("L6"); ok || got != Unknown {
		t.Fatalf("Parse(L6) = %q, %v, want unknown false", got, ok)
	}
}
