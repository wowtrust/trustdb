// Package modelsuite validates the cryptographic-suite binding of V2 model
// objects before they cross a wire, WAL, proofstore, or composition boundary.
package modelsuite

import (
	"fmt"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/internal/model"
)

func Require(expected cryptosuite.ID, value any) error {
	if _, err := cryptosuite.RequireAvailable(expected); err != nil {
		return err
	}
	require := func(name string, actual ...cryptosuite.ID) error {
		if err := cryptosuite.RequireSame(expected, actual...); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	}
	switch v := value.(type) {
	case model.ClientClaim:
		return require("client claim", v.CryptoSuite)
	case model.SignedClaim:
		return require("signed claim", v.CryptoSuite, v.Claim.CryptoSuite)
	case model.ServerRecord:
		return require("server record", v.CryptoSuite)
	case model.AcceptedReceipt:
		return require("accepted receipt", v.CryptoSuite)
	case model.CommittedReceipt:
		return require("committed receipt", v.CryptoSuite)
	case model.ProofBundle:
		actual := []cryptosuite.ID{v.CryptoSuite}
		if v.SignedClaim.SchemaVersion != "" {
			actual = append(actual, v.SignedClaim.CryptoSuite)
			if v.SignedClaim.Claim.SchemaVersion != "" {
				actual = append(actual, v.SignedClaim.Claim.CryptoSuite)
			}
		}
		if v.ServerRecord.SchemaVersion != "" {
			actual = append(actual, v.ServerRecord.CryptoSuite)
		}
		if v.AcceptedReceipt.SchemaVersion != "" {
			actual = append(actual, v.AcceptedReceipt.CryptoSuite)
		}
		if v.CommittedReceipt.SchemaVersion != "" {
			actual = append(actual, v.CommittedReceipt.CryptoSuite)
		}
		return require("proof bundle", actual...)
	case model.SingleProof:
		actual := []cryptosuite.ID{v.CryptoSuite, v.ProofBundle.CryptoSuite}
		if v.GlobalProof != nil {
			actual = append(actual, v.GlobalProof.CryptoSuite, v.GlobalProof.STH.CryptoSuite)
		}
		if v.AnchorResult != nil {
			actual = append(actual, v.AnchorResult.CryptoSuite, v.AnchorResult.STH.CryptoSuite)
		}
		for i := range v.IdentityEvidence {
			actual = append(actual, v.IdentityEvidence[i].CryptoSuite)
			for j := range v.IdentityEvidence[i].CertificateStatuses {
				actual = append(actual, v.IdentityEvidence[i].CertificateStatuses[j].CryptoSuite)
			}
		}
		return require("single proof", actual...)
	case model.RecordIndex:
		return require("record index", v.CryptoSuite)
	case model.RecordStatus:
		return require("record status", v.CryptoSuite)
	case model.StatusRefresh:
		return require("status refresh", v.CryptoSuite)
	case model.BatchRoot:
		return require("batch root", v.CryptoSuite)
	case model.WALCheckpoint:
		return require("WAL checkpoint", v.CryptoSuite)
	case model.BatchManifest:
		return require("batch manifest", v.CryptoSuite)
	case model.BatchTreeLeaf:
		return require("batch tree leaf", v.CryptoSuite)
	case model.BatchTreeNode:
		return require("batch tree node", v.CryptoSuite)
	case model.BatchTreeSnapshot:
		return require("batch tree snapshot", v.CryptoSuite)
	case model.GlobalLogLeaf:
		return require("global log leaf", v.CryptoSuite)
	case model.GlobalLogNode:
		return require("global log node", v.CryptoSuite)
	case model.GlobalLogState:
		return require("global log state", v.CryptoSuite)
	case model.SignedTreeHead:
		return require("signed tree head", v.CryptoSuite)
	case model.GlobalLogProof:
		return require("global log proof", v.CryptoSuite, v.STH.CryptoSuite)
	case model.GlobalLogTile:
		return require("global log tile", v.CryptoSuite)
	case model.GlobalLogOutboxItem:
		actual := []cryptosuite.ID{v.CryptoSuite}
		if v.BatchRoot.SchemaVersion != "" {
			actual = append(actual, v.BatchRoot.CryptoSuite)
		}
		if v.STH.TreeSize != 0 {
			actual = append(actual, v.STH.CryptoSuite)
		}
		return require("global log outbox", actual...)
	case model.GlobalLogAppend:
		actual := []cryptosuite.ID{v.Leaf.CryptoSuite, v.State.CryptoSuite, v.STH.CryptoSuite}
		for i := range v.Nodes {
			actual = append(actual, v.Nodes[i].CryptoSuite)
		}
		return require("global log append", actual...)
	case model.STHAnchorCandidate:
		return require("STH anchor candidate", v.STH.CryptoSuite)
	case model.STHAnchorResult:
		return require("STH anchor result", v.CryptoSuite, v.STH.CryptoSuite)
	case model.STHAnchorLatestReference:
		if v.SchemaVersion == model.SchemaSTHAnchorLatestEmpty {
			return nil
		}
		return require("STH anchor latest reference", v.CryptoSuite)
	case model.STHAnchorSchedule:
		actual := []cryptosuite.ID{v.CryptoSuite}
		if v.Pending != nil {
			actual = append(actual, v.Pending.Target.CryptoSuite)
		}
		if v.InFlight != nil {
			actual = append(actual, v.InFlight.Target.CryptoSuite)
		}
		return require("STH anchor schedule", actual...)
	case model.L5CoverageCheckpoint:
		return require("L5 coverage checkpoint", v.CryptoSuite)
	case model.IdempotencyDecision:
		return require("idempotency decision", v.CryptoSuite, v.Record.CryptoSuite, v.Accepted.CryptoSuite)
	case model.ClientKey:
		actual := []cryptosuite.ID{v.CryptoSuite}
		if len(v.KeyDescriptor) != 0 {
			descriptor, err := keydescriptor.Unmarshal(v.KeyDescriptor)
			if err != nil {
				return fmt.Errorf("client key descriptor: %w", err)
			}
			actual = append(actual, descriptor.CryptoSuite)
		}
		return require("client key", actual...)
	case model.KeyEvent:
		actual := []cryptosuite.ID{v.CryptoSuite}
		if len(v.KeyDescriptor) != 0 {
			descriptor, err := keydescriptor.Unmarshal(v.KeyDescriptor)
			if err != nil {
				return fmt.Errorf("key event descriptor: %w", err)
			}
			actual = append(actual, descriptor.CryptoSuite)
		}
		return require("key event", actual...)
	default:
		return fmt.Errorf("unsupported suite-bound model type %T", value)
	}
}
