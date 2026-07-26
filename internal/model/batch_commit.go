package model

import "github.com/wowtrust/trustdb/v2/internal/cryptosuite"

const (
	BatchComputePlanOnly     = "plan_only"
	BatchComputeMaterialized = "materialized"
)

func ValidBatchManifestState(state string) bool {
	switch state {
	case BatchStatePreparing, BatchStatePrepared, BatchStateCommitted, BatchStateFailed:
		return true
	default:
		return false
	}
}

type BatchComputeOptions struct {
	Mode        string
	IncludeTree bool
}

type BatchTreeSnapshot struct {
	CryptoSuite    cryptosuite.ID
	BatchID        string
	CreatedAtUnixN int64
	RecordIDs      []string
	LeafHashes     [][cryptosuite.DigestSize]byte
	Nodes          []BatchTreeSnapshotNode
}

type BatchTreeSnapshotNode struct {
	Level      uint64
	StartIndex uint64
	Width      uint64
	Hash       [cryptosuite.DigestSize]byte
}

type BatchCommit struct {
	TreeAlg string
	Root    BatchRoot
	Indexes []RecordIndex
	Tree    BatchTreeSnapshot
	Bundles []ProofBundle
}
