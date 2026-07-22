package app

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/merkle"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/receipt"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/trusterr"
	"github.com/wowtrust/trustdb/internal/wal"
)

type LocalEngine struct {
	ServerID string
	// LogID scopes batch and transparency-log identifiers for this compute node (shared proofstore).
	LogID            string
	ServerKeyID      string
	ClientPublicKey  ed25519.PublicKey
	ClientKeys       ClientKeyResolver
	ServerPrivateKey ed25519.PrivateKey
	ProofWorkers     int
	WAL              *wal.Writer
	Idempotency      *IdempotencyIndex
	// DurableIdempotency resolves committed keys whose accepted WAL records
	// were skipped below a trusted checkpoint. Nil preserves the WAL-only path.
	DurableIdempotency DurableIdempotencyReader
	// DurableRecords resolves committed unkeyed claims by deterministic record ID.
	DurableRecords DurableRecordReader
	Now            func() time.Time
}

type ClientKeyResolver interface {
	LookupClientKeyAt(tenantID, clientID, keyID string, at time.Time) (model.ClientKey, error)
}

type ReplayedAccepted struct {
	Signed   model.SignedClaim
	Record   model.ServerRecord
	Accepted model.AcceptedReceipt
}

// Submit validates a signed claim, appends it to the WAL on first submission,
// and returns the resulting server record and accepted receipt. The
// idempotent return value is true when the claim matches an existing
// idempotency_key entry and the returned pair was generated on a previous
// submission; callers forwarding to downstream pipelines (e.g. batch
// enqueue) should skip idempotent replays to avoid duplicate work. Conflicts
// on (tenant_id, client_id, idempotency_key) with a different claim body are
// surfaced as CodeAlreadyExists.
func (e LocalEngine) Submit(ctx context.Context, signed model.SignedClaim) (model.ServerRecord, model.AcceptedReceipt, bool, error) {
	if e.WAL == nil {
		return model.ServerRecord{}, model.AcceptedReceipt{}, false, fmt.Errorf("app: WAL writer is nil")
	}
	now := e.now()
	verified, keyStatus, claimHash, sigHash, err := e.validateSigned(signed, now)
	if err != nil {
		return model.ServerRecord{}, model.AcceptedReceipt{}, false, err
	}
	idemKey := IdempotencyKey(signed.Claim.TenantID, signed.Claim.ClientID, signed.Claim.IdempotencyKey)
	identity := model.IdempotencyIdentity{
		TenantID:       signed.Claim.TenantID,
		ClientID:       signed.Claim.ClientID,
		IdempotencyKey: signed.Claim.IdempotencyKey,
	}
	build := func() (model.ServerRecord, model.AcceptedReceipt, error) {
		payload, err := cborx.Marshal(signed)
		if err != nil {
			return model.ServerRecord{}, model.AcceptedReceipt{}, err
		}
		pos, _, err := e.WAL.AppendAt(ctx, payload, now)
		if err != nil {
			return model.ServerRecord{}, model.AcceptedReceipt{}, err
		}
		return e.buildAccepted(signed, verified, keyStatus, claimHash, sigHash, pos, now)
	}
	if e.Idempotency == nil {
		record, accepted, err := build()
		return record, accepted, false, err
	}
	if idemKey == "" {
		record, accepted, loaded, conflict, err := e.Idempotency.RememberDurableRecord(
			ctx,
			RecordIDKey(verified.RecordID),
			verified.RecordID,
			claimHash,
			e.DurableRecords,
			build,
		)
		if err != nil {
			return model.ServerRecord{}, model.AcceptedReceipt{}, false, err
		}
		if conflict {
			return model.ServerRecord{}, model.AcceptedReceipt{}, false, trusterr.New(
				trusterr.CodeAlreadyExists,
				fmt.Sprintf("record_id %q already associated with a different claim", verified.RecordID),
			)
		}
		return record, accepted, loaded, nil
	}
	record, accepted, loaded, conflict, err := e.Idempotency.RememberDurable(
		ctx,
		idemKey,
		identity,
		claimHash,
		e.DurableIdempotency,
		build,
	)
	if err != nil {
		return model.ServerRecord{}, model.AcceptedReceipt{}, false, err
	}
	if conflict {
		return model.ServerRecord{}, model.AcceptedReceipt{}, false, trusterr.New(
			trusterr.CodeAlreadyExists,
			fmt.Sprintf("idempotency_key %q already associated with a different claim", signed.Claim.IdempotencyKey),
		)
	}
	return record, accepted, loaded, nil
}

// MarkRecordCommitted converts an unkeyed live acceptance into the bounded
// durable cache after its proof bundle and committed manifest are published.
func (e LocalEngine) MarkRecordCommitted(recordID string) {
	if e.Idempotency == nil || e.DurableRecords == nil {
		return
	}
	e.Idempotency.ForgetCommitted(RecordIDKey(recordID), recordID)
}

// MarkIdempotencyCommitted evicts the process-local acceptance only after its
// exact response has been atomically published in the durable projection.
func (e LocalEngine) MarkIdempotencyCommitted(identity model.IdempotencyIdentity, recordID string) {
	if e.Idempotency == nil || e.DurableIdempotency == nil {
		return
	}
	e.Idempotency.ForgetCommitted(
		IdempotencyKey(identity.TenantID, identity.ClientID, identity.IdempotencyKey),
		recordID,
	)
}

func (e LocalEngine) ReplayAccepted(record wal.Record) (ReplayedAccepted, error) {
	var signed model.SignedClaim
	if err := cborx.UnmarshalLimit(record.Payload, &signed, len(record.Payload)); err != nil {
		return ReplayedAccepted{}, err
	}
	receivedAt := time.Unix(0, record.UnixNano).UTC()
	verified, keyStatus, claimHash, sigHash, err := e.validateSigned(signed, receivedAt)
	if err != nil {
		return ReplayedAccepted{}, err
	}
	serverRecord, accepted, err := e.buildAccepted(
		signed,
		verified,
		keyStatus,
		claimHash,
		sigHash,
		record.Position,
		receivedAt,
	)
	if err != nil {
		return ReplayedAccepted{}, err
	}
	return ReplayedAccepted{
		Signed:   signed,
		Record:   serverRecord,
		Accepted: accepted,
	}, nil
}

func (e LocalEngine) validateSigned(signed model.SignedClaim, receivedAt time.Time) (claim.Verified, string, []byte, []byte, error) {
	clientPub, keyStatus, err := e.resolveClientKey(signed, receivedAt)
	if err != nil {
		return claim.Verified{}, "", nil, nil, err
	}
	verified, err := claim.Verify(signed, clientPub)
	if err != nil {
		return claim.Verified{}, "", nil, nil, err
	}
	claimHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, verified.ClaimCBOR)
	if err != nil {
		return claim.Verified{}, "", nil, nil, err
	}
	sigHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, signed.Signature.Signature)
	if err != nil {
		return claim.Verified{}, "", nil, nil, err
	}
	return verified, keyStatus, claimHash, sigHash, nil
}

func (e LocalEngine) buildAccepted(
	signed model.SignedClaim,
	verified claim.Verified,
	keyStatus string,
	claimHash []byte,
	sigHash []byte,
	pos model.WALPosition,
	receivedAt time.Time,
) (model.ServerRecord, model.AcceptedReceipt, error) {
	record := model.ServerRecord{
		SchemaVersion:       model.SchemaServerRecord,
		RecordID:            verified.RecordID,
		TenantID:            signed.Claim.TenantID,
		ClientID:            signed.Claim.ClientID,
		KeyID:               signed.Claim.KeyID,
		ClaimHash:           claimHash,
		ClientSignatureHash: sigHash,
		ReceivedAtUnixN:     receivedAt.UnixNano(),
		WAL:                 pos,
		Validation: model.Validation{
			PolicyVersion:       model.DefaultValidationPolicy,
			HashAlgAllowed:      true,
			SignatureAlgAllowed: true,
			KeyStatus:           keyStatus,
		},
	}
	accepted := model.AcceptedReceipt{
		SchemaVersion:   model.SchemaAcceptedReceipt,
		RecordID:        record.RecordID,
		Status:          "accepted",
		ServerID:        e.ServerID,
		ReceivedAtUnixN: receivedAt.UnixNano(),
		WAL:             pos,
	}
	accepted, err := receipt.SignAccepted(accepted, e.ServerKeyID, e.ServerPrivateKey)
	if err != nil {
		return model.ServerRecord{}, model.AcceptedReceipt{}, err
	}
	return record, accepted, nil
}

func (e LocalEngine) resolveClientKey(signed model.SignedClaim, receivedAt time.Time) (ed25519.PublicKey, string, error) {
	if e.ClientKeys != nil {
		key, err := e.ClientKeys.LookupClientKeyAt(
			signed.Claim.TenantID,
			signed.Claim.ClientID,
			signed.Claim.KeyID,
			receivedAt,
		)
		if err != nil {
			return nil, "", err
		}
		if key.Alg != model.DefaultSignatureAlg {
			return nil, "", fmt.Errorf("app: unsupported client key alg: %s", key.Alg)
		}
		if len(key.PublicKey) != ed25519.PublicKeySize {
			return nil, "", fmt.Errorf("app: invalid resolved client public key size: %d", len(key.PublicKey))
		}
		return ed25519.PublicKey(key.PublicKey), key.Status, nil
	}
	if len(e.ClientPublicKey) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("app: client public key or key resolver required")
	}
	return e.ClientPublicKey, model.KeyStatusValid, nil
}

func (e LocalEngine) CommitBatch(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) ([]model.ProofBundle, error) {
	result, err := e.ComputeBatch(context.Background(), batchID, closedAt, signed, records, accepted, model.BatchComputeOptions{
		Mode: model.BatchComputeMaterialized,
	})
	return result.Bundles, err
}

func (e LocalEngine) CommitBatchIndexes(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) (model.BatchRoot, []model.RecordIndex, error) {
	result, err := e.ComputeBatch(context.Background(), batchID, closedAt, signed, records, accepted, model.BatchComputeOptions{
		Mode: model.BatchComputePlanOnly,
	})
	return result.Root, result.Indexes, err
}

func (e LocalEngine) ComputeBatch(ctx context.Context, batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt, opts model.BatchComputeOptions) (model.BatchCommit, error) {
	if err := ctx.Err(); err != nil {
		return model.BatchCommit{}, err
	}
	if len(records) == 0 || len(records) != len(signed) || len(records) != len(accepted) {
		return model.BatchCommit{}, fmt.Errorf("app: inconsistent batch input sizes")
	}
	tree, err := merkle.Build(records)
	if err != nil {
		return model.BatchCommit{}, err
	}
	if closedAt.IsZero() {
		closedAt = e.now()
	}
	closedAt = closedAt.UTC()
	root := tree.Root()
	result := model.BatchCommit{
		Root: model.BatchRoot{
			SchemaVersion: model.SchemaBatchRoot,
			BatchID:       batchID,
			NodeID:        e.ServerID,
			LogID:         e.LogID,
			BatchRoot:     append([]byte(nil), root...),
			TreeSize:      uint64(len(records)),
			ClosedAtUnixN: closedAt.UnixNano(),
		},
		Indexes: make([]model.RecordIndex, len(records)),
	}
	proofLevel := "L2"
	materialized := opts.Mode == model.BatchComputeMaterialized
	if materialized {
		proofLevel = "L3"
	}
	for i := range records {
		result.Indexes[i] = model.RecordIndexFromBatchInputs(
			signed[i], records[i], accepted[i], e.ServerID, e.LogID,
			batchID, uint64(i), closedAt.UnixNano(), proofLevel,
		)
	}
	if opts.IncludeTree {
		result.Tree = compactBatchTree(batchID, closedAt.UnixNano(), records, tree)
	}
	if !materialized {
		return result, nil
	}

	result.Bundles = make([]model.ProofBundle, len(records))
	errs := make([]error, len(records))
	jobs := make(chan int)
	workers := e.proofWorkerCount(len(records))
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if err := ctx.Err(); err != nil {
					errs[i] = err
					continue
				}
				leaf, err := tree.LeafHashView(i)
				if err != nil {
					errs[i] = err
					continue
				}
				proof, err := tree.ProofView(i)
				if err != nil {
					errs[i] = err
					continue
				}
				committed := model.CommittedReceipt{
					SchemaVersion: model.SchemaCommittedReceipt,
					RecordID:      records[i].RecordID,
					Status:        "committed",
					BatchID:       batchID,
					LeafIndex:     uint64(i),
					LeafHash:      leaf,
					BatchRoot:     append([]byte(nil), root...),
					ClosedAtUnixN: closedAt.UnixNano(),
					NodeID:        e.ServerID,
					LogID:         e.LogID,
				}
				committed, err = receipt.SignCommitted(committed, e.ServerKeyID, e.ServerPrivateKey)
				if err != nil {
					errs[i] = err
					continue
				}
				result.Bundles[i] = model.ProofBundle{
					SchemaVersion:    model.SchemaProofBundle,
					RecordID:         records[i].RecordID,
					NodeID:           e.ServerID,
					LogID:            e.LogID,
					SignedClaim:      signed[i],
					ServerRecord:     records[i],
					AcceptedReceipt:  accepted[i],
					CommittedReceipt: committed,
					BatchProof: model.BatchProof{
						TreeAlg:   model.DefaultMerkleTreeAlg,
						LeafIndex: uint64(i),
						TreeSize:  uint64(len(records)),
						AuditPath: proof,
					},
				}
			}
		}()
	}
	for i := range records {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return model.BatchCommit{}, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			return model.BatchCommit{}, errs[i]
		}
	}
	return result, nil
}

func (e LocalEngine) proofWorkerCount(records int) int {
	workers := e.ProofWorkers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
		if workers > 32 {
			workers = 32
		}
	}
	if workers > records {
		workers = records
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

func compactBatchTree(batchID string, createdAtUnixN int64, records []model.ServerRecord, tree merkle.Tree) model.BatchTreeSnapshot {
	recordIDs := make([]string, len(records))
	for i := range records {
		recordIDs[i] = records[i].RecordID
	}
	leaves := append([][32]byte(nil), tree.CompactLeaves()...)
	compactNodes := tree.CompactNodes()
	sort.Slice(compactNodes, func(i, j int) bool {
		if compactNodes[i].Level != compactNodes[j].Level {
			return compactNodes[i].Level < compactNodes[j].Level
		}
		return compactNodes[i].StartIndex < compactNodes[j].StartIndex
	})
	nodes := make([]model.BatchTreeSnapshotNode, len(compactNodes))
	for i := range compactNodes {
		nodes[i] = model.BatchTreeSnapshotNode{
			Level:      compactNodes[i].Level,
			StartIndex: compactNodes[i].StartIndex,
			Width:      compactNodes[i].Width,
			Hash:       compactNodes[i].Hash,
		}
	}
	return model.BatchTreeSnapshot{
		BatchID:        batchID,
		CreatedAtUnixN: createdAtUnixN,
		RecordIDs:      recordIDs,
		LeafHashes:     leaves,
		Nodes:          nodes,
	}
}

func (e LocalEngine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}
