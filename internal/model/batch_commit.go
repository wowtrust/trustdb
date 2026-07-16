package model

import "crypto/sha256"

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
	BatchID        string
	CreatedAtUnixN int64
	RecordIDs      []string
	LeafHashes     [][sha256.Size]byte
	Nodes          []BatchTreeSnapshotNode
}

type BatchTreeSnapshotNode struct {
	Level      uint64
	StartIndex uint64
	Width      uint64
	Hash       [sha256.Size]byte
}

type BatchCommit struct {
	Root    BatchRoot
	Indexes []RecordIndex
	Tree    BatchTreeSnapshot
	Bundles []ProofBundle
}
