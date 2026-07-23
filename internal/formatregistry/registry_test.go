package formatregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
)

func TestRegistryPinsCurrentAndReservedGenerations(t *testing.T) {
	want := map[string]struct {
		family       Family
		version      uint16
		availability Availability
		migration    MigrationPolicy
		maxBytes     int64
	}{
		ModelV1:       {FamilyModel, 1, AvailabilityAvailable, MigrationRetireOnCutover, 0},
		ModelV2:       {FamilyModel, 2, AvailabilityReserved, MigrationDestructiveCutover, MaxStoredObjectBytesV2},
		SingleProofV1: {FamilySingleProof, 1, AvailabilityAvailable, MigrationRetireOnCutover, 16 << 20},
		SingleProofV2: {FamilySingleProof, 2, AvailabilityReserved, MigrationDestructiveCutover, MaxSingleProofBytesV2},
		BackupV4:      {FamilyBackup, 4, AvailabilityAvailable, MigrationRetireOnCutover, 128 << 20},
		BackupV5:      {FamilyBackup, 5, AvailabilityReserved, MigrationDestructiveCutover, MaxBackupEntryBytesV2},
		WALV1:         {FamilyWAL, 1, AvailabilityAvailable, MigrationRetireOnCutover, 0},
		WALV2:         {FamilyWAL, 2, AvailabilityReserved, MigrationDestructiveCutover, MaxStoredObjectBytesV2},
		ProofstoreV4:  {FamilyProofstore, 4, AvailabilityAvailable, MigrationRetireOnCutover, 64 << 20},
		ProofstoreV5:  {FamilyProofstore, 5, AvailabilityReserved, MigrationDestructiveCutover, MaxStoredObjectBytesV2},
		HTTPV1:        {FamilyHTTP, 1, AvailabilityAvailable, MigrationRetireOnCutover, 16 << 20},
		HTTPV2:        {FamilyHTTP, 2, AvailabilityReserved, MigrationDestructiveCutover, MaxTransportMessageBytesV2},
		GRPCV1:        {FamilyGRPC, 1, AvailabilityAvailable, MigrationRetireOnCutover, 16 << 20},
		GRPCV2:        {FamilyGRPC, 2, AvailabilityReserved, MigrationDestructiveCutover, MaxTransportMessageBytesV2},
		NATSV1:        {FamilyNATS, 1, AvailabilityAvailable, MigrationRetireOnCutover, 1 << 20},
		NATSV2:        {FamilyNATS, 2, AvailabilityReserved, MigrationDestructiveCutover, MaxTransportMessageBytesV2},
		SDKV1:         {FamilySDK, 1, AvailabilityAvailable, MigrationRetireOnCutover, 16 << 20},
		SDKV2:         {FamilySDK, 2, AvailabilityReserved, MigrationDestructiveCutover, MaxTransportMessageBytesV2},
	}

	all := All()
	if len(all) != len(want) {
		t.Fatalf("All() count = %d, want %d", len(all), len(want))
	}
	for _, descriptor := range all {
		expected, ok := want[descriptor.Identifier]
		if !ok {
			t.Fatalf("unexpected descriptor %q", descriptor.Identifier)
		}
		if descriptor.Family != expected.family ||
			descriptor.Version != expected.version ||
			descriptor.Availability != expected.availability ||
			descriptor.Migration != expected.migration ||
			descriptor.MaxBytes != expected.maxBytes {
			t.Fatalf("descriptor %q = %#v, want family=%s version=%d availability=%s migration=%s max=%d",
				descriptor.Identifier,
				descriptor,
				expected.family,
				expected.version,
				expected.availability,
				expected.migration,
				expected.maxBytes,
			)
		}
		if descriptor.CanonicalEncoding == "" || !descriptor.RejectUnknownSuites {
			t.Fatalf("descriptor %q does not fail closed: %#v", descriptor.Identifier, descriptor)
		}
		if descriptor.Identifier == BackupV4 {
			if descriptor.RejectUnknownFields || descriptor.RejectUnknownEntries {
				t.Fatalf("backup v4 strictness no longer matches the implemented decoder: %#v", descriptor)
			}
		} else if !descriptor.RejectUnknownFields || !descriptor.RejectUnknownEntries {
			t.Fatalf("descriptor %q must reject unknown fields and entries", descriptor.Identifier)
		}
		if descriptor.Availability == AvailabilityAvailable {
			if !reflect.DeepEqual(descriptor.AllowedSuites, []cryptosuite.ID{cryptosuite.INTLV1}) || descriptor.SuiteField != "" {
				t.Fatalf("current descriptor %q has unexpected suite binding: %#v", descriptor.Identifier, descriptor)
			}
		} else {
			if !reflect.DeepEqual(descriptor.AllowedSuites, []cryptosuite.ID{cryptosuite.CNSMV1, cryptosuite.INTLV1}) || descriptor.SuiteField != "crypto_suite" {
				t.Fatalf("reserved descriptor %q has unexpected suite binding: %#v", descriptor.Identifier, descriptor)
			}
		}
	}
}

func TestRegistryAllIsSortedAndDefensivelyCopied(t *testing.T) {
	all := All()
	identifiers := make([]string, len(all))
	for i := range all {
		identifiers[i] = all[i].Identifier
	}
	if !sort.StringsAreSorted(identifiers) {
		t.Fatalf("All() identifiers are not sorted: %v", identifiers)
	}

	first := all[0]
	first.AllowedSuites[0] = "MUTATED"
	again, ok := Lookup(first.Identifier)
	if !ok {
		t.Fatalf("Lookup(%q) failed", first.Identifier)
	}
	if again.AllowedSuites[0] == "MUTATED" {
		t.Fatal("registry leaked mutable suite slice")
	}
}

func TestRuntimeGatesRejectReservedFormatsAndSuites(t *testing.T) {
	if _, _, err := RequireWritable(ModelV1, cryptosuite.INTLV1); err != nil {
		t.Fatalf("RequireWritable(current INTL_V1) error = %v", err)
	}
	if _, _, err := RequireWritable(ModelV2, cryptosuite.INTLV1); !errors.Is(err, ErrUnavailableFormat) {
		t.Fatalf("RequireWritable(reserved format) error = %v, want ErrUnavailableFormat", err)
	}
	if _, _, err := RequireWritable(ModelV1, cryptosuite.CNSMV1); !errors.Is(err, ErrSuiteNotAllowed) {
		t.Fatalf("RequireWritable(current CN_SM_V1) error = %v, want ErrSuiteNotAllowed", err)
	}
	if err := RequireSuite(ModelV2, cryptosuite.CNSMV1); err != nil {
		t.Fatalf("RequireSuite(reserved planned combination) error = %v", err)
	}
	if err := RequireSuite(ModelV2, cryptosuite.ID("UNKNOWN")); !errors.Is(err, cryptosuite.ErrUnknownSuite) {
		t.Fatalf("RequireSuite(unknown) error = %v, want cryptosuite.ErrUnknownSuite", err)
	}
	if _, err := RequireKnown("trustdb.model-generation"); !errors.Is(err, ErrUnknownFormat) {
		t.Fatalf("RequireKnown(unversioned) error = %v, want ErrUnknownFormat", err)
	}
}

func TestModelSchemaTransitionsCoverCurrentModelSchemas(t *testing.T) {
	wantCurrent := map[string]string{
		"accepted_receipt":        model.SchemaAcceptedReceipt,
		"batch_manifest":          model.SchemaBatchManifest,
		"batch_root":              model.SchemaBatchRoot,
		"batch_tree_leaf":         model.SchemaBatchTreeLeaf,
		"batch_tree_node":         model.SchemaBatchTreeNode,
		"client_claim":            model.SchemaClientClaim,
		"committed_receipt":       model.SchemaCommittedReceipt,
		"global_log_leaf":         model.SchemaGlobalLogLeaf,
		"global_log_node":         model.SchemaGlobalLogNode,
		"global_log_outbox":       model.SchemaGlobalLogOutbox,
		"global_log_proof":        model.SchemaGlobalLogProof,
		"global_log_state":        model.SchemaGlobalLogState,
		"global_log_tile":         model.SchemaGlobalLogTile,
		"idempotency_decision":    model.SchemaIdempotencyDecision,
		"key_event":               model.SchemaKeyEvent,
		"l5_coverage_checkpoint":  model.SchemaL5Coverage,
		"proof_bundle":            model.SchemaProofBundle,
		"record_index":            model.SchemaRecordIndex,
		"server_record":           model.SchemaServerRecord,
		"signed_claim":            model.SchemaSignedClaim,
		"signed_tree_head":        model.SchemaSignedTreeHead,
		"sth_anchor_latest":       model.SchemaSTHAnchorLatest,
		"sth_anchor_latest_empty": model.SchemaSTHAnchorLatestEmpty,
		"sth_anchor_result":       model.SchemaSTHAnchorResult,
		"sth_anchor_schedule":     model.SchemaSTHAnchorSchedule,
		"wal_checkpoint":          model.SchemaWALCheckpointContiguous,
	}

	transitions := ModelSchemas()
	if len(transitions) != len(wantCurrent) {
		t.Fatalf("ModelSchemas() count = %d, want %d", len(transitions), len(wantCurrent))
	}
	seenNext := make(map[string]struct{}, len(transitions))
	for _, transition := range transitions {
		current, ok := wantCurrent[transition.Artifact]
		if !ok {
			t.Fatalf("unexpected model artifact %q", transition.Artifact)
		}
		if transition.Current != current {
			t.Fatalf("artifact %q current schema = %q, want %q", transition.Artifact, transition.Current, current)
		}
		if transition.Next == "" || transition.Next == transition.Current {
			t.Fatalf("artifact %q has invalid next schema %q", transition.Artifact, transition.Next)
		}
		if _, exists := seenNext[transition.Next]; exists {
			t.Fatalf("duplicate next schema %q", transition.Next)
		}
		seenNext[transition.Next] = struct{}{}
	}
}

func TestModelSchemasReturnsDefensiveCopy(t *testing.T) {
	first := ModelSchemas()
	first[0].Artifact = "mutated"
	if ModelSchemas()[0].Artifact == "mutated" {
		t.Fatal("ModelSchemas leaked mutable registry storage")
	}
}

func TestValidateNamespaceTransitionRequiresFreshLogAndStore(t *testing.T) {
	current := NamespaceBinding{
		FormatIdentifier: ModelV1,
		LogID:            "log-intl-v1",
		StorageNamespace: "proofstore/intl-v1",
		NonEmpty:         true,
	}
	if err := ValidateNamespaceTransition(current, current); err != nil {
		t.Fatalf("same-format transition error = %v", err)
	}
	if err := ValidateNamespaceTransition(current, NamespaceBinding{
		FormatIdentifier: ModelV2,
		LogID:            current.LogID,
		StorageNamespace: "proofstore/crypto-agile-v2",
	}); !errors.Is(err, ErrFormatNamespaceReuse) {
		t.Fatalf("reused log_id error = %v, want ErrFormatNamespaceReuse", err)
	}
	if err := ValidateNamespaceTransition(current, NamespaceBinding{
		FormatIdentifier: ModelV2,
		LogID:            "log-crypto-agile-v2",
		StorageNamespace: current.StorageNamespace,
	}); !errors.Is(err, ErrFormatNamespaceReuse) {
		t.Fatalf("reused storage namespace error = %v, want ErrFormatNamespaceReuse", err)
	}
	if err := ValidateNamespaceTransition(current, NamespaceBinding{
		FormatIdentifier: ModelV2,
		LogID:            "log-crypto-agile-v2",
		StorageNamespace: "proofstore/crypto-agile-v2",
	}); err != nil {
		t.Fatalf("fresh transition error = %v", err)
	}
}

func TestValidateNamespaceTransitionRejectsUnboundNonEmptyData(t *testing.T) {
	err := ValidateNamespaceTransition(
		NamespaceBinding{NonEmpty: true},
		NamespaceBinding{FormatIdentifier: ModelV1, LogID: "log", StorageNamespace: "store"},
	)
	if !errors.Is(err, ErrUnboundNonEmptyData) {
		t.Fatalf("transition error = %v, want ErrUnboundNonEmptyData", err)
	}
}

func TestCryptoAgileEvidenceLimitsAreInternallyConsistent(t *testing.T) {
	if MaxCertificateCountV2 <= 0 || MaxCertificateBytesV2 <= 0 || MaxCertificateChainBytesV2 <= 0 {
		t.Fatal("certificate limits must be positive")
	}
	if MaxCertificateBytesV2 > MaxCertificateChainBytesV2 {
		t.Fatal("one certificate cannot exceed the aggregate chain limit")
	}
	if MaxBCOSReceiptProofBytesV2 > MaxAnchorEvidenceBytesV2 || MaxBCOSFinalityBytesV2 > MaxAnchorEvidenceBytesV2 {
		t.Fatal("BCOS components cannot exceed the anchor evidence limit")
	}
	if MaxAnchorEvidenceBytesV2 > MaxSingleProofBytesV2 || MaxSingleProofBytesV2 > MaxTransportMessageBytesV2 {
		t.Fatal("anchor, single-proof, and transport limits are inconsistent")
	}
	if int64(MaxTransportMessageBytesV2) > MaxBackupEntryBytesV2 || MaxTransportMessageBytesV2 > MaxStoredObjectBytesV2 {
		t.Fatal("transport evidence cannot exceed storage or backup entry limits")
	}
}

func TestRegistrySnapshotCanonicalCBORGolden(t *testing.T) {
	encoded, err := cborx.Marshal(Snapshot())
	if err != nil {
		t.Fatalf("marshal registry snapshot: %v", err)
	}
	digest := sha256.Sum256(encoded)
	const wantSHA256 = "61e7a3cd35e840af8f15c35dfce6d14fe04b53f4a4c4ec391ffc8b6ae5e8ceb3"
	if got := hex.EncodeToString(digest[:]); got != wantSHA256 {
		t.Fatalf("registry snapshot SHA-256 = %s, want %s", got, wantSHA256)
	}
}
