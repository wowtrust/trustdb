// Package prooflevel defines the TrustDB L1-L5 proof ladder in one place.
//
// The package is intentionally pure: callers provide evidence that is already
// present or already verified, and the evaluator returns the strongest level
// reachable without inventing intermediate trust.
package prooflevel

import "strings"

type Level string

const (
	Unknown Level = ""
	L1      Level = "L1"
	L2      Level = "L2"
	L3      Level = "L3"
	L4      Level = "L4"
	L5      Level = "L5"
)

type Evidence struct {
	ContentHash      bool
	ClientSignature  bool
	AcceptedReceipt  bool
	CommittedReceipt bool
	BatchProof       bool
	GlobalLogProof   bool
	STHAnchorResult  bool
}

type Definition struct {
	Level       Level
	Label       string
	Requirement string
}

var ladder = []Definition{
	{Level: L1, Label: "local content", Requirement: "content hash matches the signed client claim and the client signature is valid"},
	{Level: L2, Label: "accepted", Requirement: "L1 plus a valid server AcceptedReceipt"},
	{Level: L3, Label: "batch committed", Requirement: "L2 plus a valid CommittedReceipt and batch Merkle inclusion proof"},
	{Level: L4, Label: "global log", Requirement: "L3 plus a valid BatchRoot -> SignedTreeHead global-log inclusion proof"},
	{Level: L5, Label: "external anchor", Requirement: "L4 plus an STH/global-root external anchor result"},
}

func Evaluate(e Evidence) Level {
	if !(e.ContentHash && e.ClientSignature) {
		return Unknown
	}
	if !e.AcceptedReceipt {
		return L1
	}
	if !(e.CommittedReceipt && e.BatchProof) {
		return L2
	}
	if !e.GlobalLogProof {
		return L3
	}
	if !e.STHAnchorResult {
		return L4
	}
	return L5
}

func EvidenceFor(level Level) Evidence {
	evidence := Evidence{}
	if AtLeast(level, L1) {
		evidence.ContentHash = true
		evidence.ClientSignature = true
	}
	if AtLeast(level, L2) {
		evidence.AcceptedReceipt = true
	}
	if AtLeast(level, L3) {
		evidence.CommittedReceipt = true
		evidence.BatchProof = true
	}
	if AtLeast(level, L4) {
		evidence.GlobalLogProof = true
	}
	if AtLeast(level, L5) {
		evidence.STHAnchorResult = true
	}
	return evidence
}

func Definitions() []Definition {
	out := make([]Definition, len(ladder))
	copy(out, ladder)
	return out
}

func Parse(raw string) (Level, bool) {
	level := Level(strings.ToUpper(strings.TrimSpace(raw)))
	switch level {
	case L1, L2, L3, L4, L5:
		return level, true
	default:
		return Unknown, false
	}
}

func Rank(level Level) int {
	switch level {
	case L1:
		return 1
	case L2:
		return 2
	case L3:
		return 3
	case L4:
		return 4
	case L5:
		return 5
	default:
		return 0
	}
}

func AtLeast(level, target Level) bool {
	return Rank(level) >= Rank(target) && Rank(target) > 0
}

func (l Level) String() string {
	return string(l)
}
