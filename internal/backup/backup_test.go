package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/internal/keyenvelope"
	"github.com/wowtrust/trustdb/v2/internal/keystore"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/proofstore"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
	"github.com/wowtrust/trustdb/v2/internal/trusterr"
)

func TestBackupV5CreateVerifyRestoreRoundTrip(t *testing.T) {
	for _, suiteID := range []cryptosuite.ID{cryptosuite.INTLV1, cryptosuite.CNSMV1} {
		for _, compression := range []string{"none", "gzip"} {
			t.Run(string(suiteID)+"/"+compression, func(t *testing.T) {
				ctx := context.Background()
				provider := newTestKEKProvider("test-kek", 0x31)
				src := newBoundTestLocalStoreForSuite(t, filepath.Join(t.TempDir(), "src"), suiteID)
				seedBackupStore(t, src, suiteID, 3, 0)

				path := filepath.Join(t.TempDir(), "proofstore.tdbackup")
				report, err := Create(ctx, src, path, Options{
					Compression: compression, FrameBytes: minFramePlainBytes,
					KEKProvider: provider, KEKKeyID: "test-backup-kek",
					Clock: func() time.Time { return time.Unix(100, 123).UTC() },
				})
				if err != nil {
					t.Fatalf("Create: %v", err)
				}
				if report.SchemaVersion != SchemaManifest || report.CryptoSuite != suiteID || report.FormatGeneration != 5 ||
					report.NodeID != "test-node" || report.LogID != "test-log" || report.NamespaceID != "test-local" ||
					report.Bundles != 3 || report.BatchTreeLeaves != 3 || report.BatchTreeNodes == 0 || report.Manifests != 1 || report.Roots != 1 {
					t.Fatalf("Create report = %+v", report)
				}
				wantDigest := cryptosuite.HashSHA256
				if suiteID == cryptosuite.CNSMV1 {
					wantDigest = cryptosuite.HashSM3
				}
				if report.DigestAlgorithm != wantDigest {
					t.Fatalf("digest = %q, want %q", report.DigestAlgorithm, wantDigest)
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(raw, []byte("record-000")) || bytes.Contains(raw, []byte("batch-001")) {
					t.Fatal("encrypted backup exposes proofstore plaintext")
				}

				verified, err := Verify(ctx, path, provider)
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if verified.BackupID != report.BackupID || len(verified.Entries) != len(report.Entries) {
					t.Fatalf("Verify report = %+v", verified)
				}

				dst := newBoundTestLocalStoreForSuite(t, filepath.Join(t.TempDir(), "dst"), suiteID)
				checkpoint := filepath.Join(t.TempDir(), "restore.checkpoint.json")
				restored, err := RestoreWithOptions(ctx, dst, path, RestoreOptions{
					Resume: true, CheckpointPath: checkpoint, KEKProviders: []keyenvelope.KEKProvider{provider},
				})
				if err != nil {
					t.Fatalf("Restore: %v", err)
				}
				if restored.Bundles != 3 || restored.BatchTreeLeaves != 3 || restored.BatchTreeNodes == 0 || restored.Manifests != 1 || restored.Roots != 1 {
					t.Fatalf("Restore report = %+v", restored)
				}
				if _, err := dst.GetBundle(ctx, "record-002"); err != nil {
					t.Fatalf("restored bundle: %v", err)
				}
				leaves, err := dst.ListBatchTreeLeaves(ctx, model.BatchTreeLeafListOptions{BatchID: "batch-001", Limit: 10})
				if err != nil || len(leaves) != 3 {
					t.Fatalf("restored batch tree leaves=%d err=%v", len(leaves), err)
				}
			})
		}
	}
}

func TestBackupV5RestoresAcrossFileAndPebbleBackends(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sourceKind proofstore.Backend
		targetKind proofstore.Backend
	}{
		{name: "file-to-pebble", sourceKind: proofstore.BackendFile, targetKind: proofstore.BackendPebble},
		{name: "pebble-to-file", sourceKind: proofstore.BackendPebble, targetKind: proofstore.BackendFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := newTestKEKProvider("test-kek", 0x39)
			src := openBoundTestStore(t, tc.sourceKind, filepath.Join(t.TempDir(), "src"), "source-namespace")
			seedBackupStore(t, src, cryptosuite.INTLV1, 3, 0)

			path := filepath.Join(t.TempDir(), "portable.tdbackup")
			if _, err := Create(ctx, src, path, testCreateOptions(provider)); err != nil {
				t.Fatalf("Create: %v", err)
			}

			dst := openBoundTestStore(t, tc.targetKind, filepath.Join(t.TempDir(), "dst"), "target-namespace")
			report, err := RestoreWithOptions(ctx, dst, path, RestoreOptions{
				KEKProviders: []keyenvelope.KEKProvider{provider},
			})
			if err != nil {
				t.Fatalf("Restore: %v", err)
			}
			if report.NamespaceID != "source-namespace" || report.TargetNamespaceID != "target-namespace" {
				t.Fatalf("restore namespace report = %+v", report)
			}
			if _, err := dst.GetBundle(ctx, "record-002"); err != nil {
				t.Fatalf("restored bundle: %v", err)
			}
			leaves, err := dst.ListBatchTreeLeaves(ctx, model.BatchTreeLeafListOptions{BatchID: "batch-001", Limit: 10})
			if err != nil || len(leaves) != 3 {
				t.Fatalf("restored batch tree leaves=%d err=%v", len(leaves), err)
			}
		})
	}
}

func TestBackupV5PreservesAnchorScheduleAndImmutableResult(t *testing.T) {
	ctx := context.Background()
	provider := newTestKEKProvider("test-kek", 0x41)
	src := newBoundTestLocalStore(t, filepath.Join(t.TempDir(), "src"))
	key := model.STHAnchorScheduleKey{NodeID: "test-node", LogID: "test-log", SinkName: "noop"}
	sth := testSTH(key, 7, 0x71)
	resultSTH := testSTH(key, 5, 0x51)
	scheduler := any(src).(proofstore.STHAnchorScheduleStore)
	if _, err := scheduler.UpsertSTHAnchorCandidate(ctx, model.STHAnchorCandidate{
		Key: key, STH: sth, ObservedAtUnixN: 10, DueAtUnixN: 20,
	}); err != nil {
		t.Fatalf("UpsertSTHAnchorCandidate: %v", err)
	}
	result := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult, CryptoSuite: cryptosuite.INTLV1,
		EvidenceStage: model.AnchorEvidenceStageLocalOnly, NodeID: key.NodeID, LogID: key.LogID,
		TreeSize: resultSTH.TreeSize, SinkName: key.SinkName, AnchorID: "anchor-5",
		RootHash: append([]byte(nil), resultSTH.RootHash...), STH: resultSTH, Proof: []byte("opaque-anchor-proof"), PublishedAtUnixN: 30,
	}
	if err := any(src).(proofstore.STHAnchorResultWriter).PutSTHAnchorResult(ctx, result); err != nil {
		t.Fatalf("PutSTHAnchorResult: %v", err)
	}

	path := filepath.Join(t.TempDir(), "anchors.tdbackup")
	if _, err := Create(ctx, src, path, testCreateOptions(provider)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	dst := newBoundTestLocalStore(t, filepath.Join(t.TempDir(), "dst"))
	if _, err := RestoreWithOptions(ctx, dst, path, RestoreOptions{KEKProviders: []keyenvelope.KEKProvider{provider}}); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	gotSchedule, found, err := any(dst).(proofstore.STHAnchorScheduleStore).GetSTHAnchorSchedule(ctx, key)
	if err != nil || !found || gotSchedule.Pending == nil || gotSchedule.Pending.Target.TreeSize != 7 {
		t.Fatalf("restored schedule=%+v found=%v err=%v", gotSchedule, found, err)
	}
	gotResult, found, err := any(dst).(proofstore.STHAnchorResultKeyedReader).GetSTHAnchorResultForKey(ctx, model.STHAnchorResultKey{
		NodeID: key.NodeID, LogID: key.LogID, SinkName: key.SinkName, TreeSize: 5,
	})
	if err != nil || !found || !bytes.Equal(gotResult.Proof, result.Proof) || gotResult.AnchorID != result.AnchorID {
		t.Fatalf("restored result=%+v found=%v err=%v", gotResult, found, err)
	}
}

func TestBackupV5PreservesKeyRegistryAuditWithoutPrivateMaterial(t *testing.T) {
	ctx := context.Background()
	provider := newTestKEKProvider("test-kek", 0x45)
	src := newBoundTestLocalStore(t, filepath.Join(t.TempDir(), "src"))
	seedBackupStore(t, src, cryptosuite.INTLV1, 1, 0)
	registryPath := filepath.Join(t.TempDir(), "keys.tdkeys")
	createTestKeyRegistry(t, registryPath)
	registryBytes, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "with-registry.tdbackup")
	opts := testCreateOptions(provider)
	opts.KeyRegistryPath = registryPath
	report, err := Create(ctx, src, path, opts)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if report.KeyRegistries != 1 || !containsString(report.Inventory.PublicEvidence, "key-registry-audit") ||
		!containsString(report.Inventory.SecretReferences, "signer-private-material:external-not-exported") {
		t.Fatalf("inventory=%+v key_registries=%d", report.Inventory, report.KeyRegistries)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, registryBytes) {
		t.Fatal("key registry audit bytes were not encrypted")
	}

	dst := newBoundTestLocalStore(t, filepath.Join(t.TempDir(), "dst"))
	if _, err := RestoreWithOptions(ctx, dst, path, RestoreOptions{KEKProviders: []keyenvelope.KEKProvider{provider}}); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("restore without recovery directory error=%v code=%s", err, trusterr.CodeOf(err))
	}
	if empty, err := restoreDestinationEmpty(ctx, dst); err != nil || !empty {
		t.Fatalf("restore published before recovery target validation: empty=%v err=%v", empty, err)
	}

	recoveryDir := filepath.Join(t.TempDir(), "recovery")
	if _, err := RestoreWithOptions(ctx, dst, path, RestoreOptions{
		KEKProviders: []keyenvelope.KEKProvider{provider}, RecoveryDir: recoveryDir,
	}); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	restored, err := os.ReadFile(filepath.Join(recoveryDir, "key-registry.tdkeys"))
	if err != nil || !bytes.Equal(restored, registryBytes) {
		t.Fatalf("restored key registry bytes changed: err=%v", err)
	}
}

func TestBackupV5RejectsMalformedKeyRegistryBeforePublishingArchive(t *testing.T) {
	ctx := context.Background()
	provider := newTestKEKProvider("test-kek", 0x47)
	src := newBoundTestLocalStore(t, filepath.Join(t.TempDir(), "src"))
	seedBackupStore(t, src, cryptosuite.INTLV1, 1, 0)
	registryPath := filepath.Join(t.TempDir(), "invalid.tdkeys")
	if err := os.WriteFile(registryPath, []byte("TDBKEYR2\nnot-a-v2-registry"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "must-not-exist.tdbackup")
	opts := testCreateOptions(provider)
	opts.KeyRegistryPath = registryPath
	_, err := Create(ctx, src, path, opts)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("error=%v code=%s", err, trusterr.CodeOf(err))
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("malformed key registry published archive: stat error=%v", statErr)
	}
}

func TestBackupV5AuthenticationFailures(t *testing.T) {
	ctx := context.Background()
	provider := newTestKEKProvider("test-kek", 0x51)
	path := createLargeTestBackup(t, provider)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong key", func(t *testing.T) {
		_, err := Verify(ctx, path, newTestKEKProvider("test-kek", 0x52))
		assertDataLoss(t, err)
	})
	t.Run("missing provider", func(t *testing.T) {
		_, err := Verify(ctx, path)
		if trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("error=%v code=%s", err, trusterr.CodeOf(err))
		}
	})
	t.Run("modified ciphertext", func(t *testing.T) {
		mutated := append([]byte(nil), original...)
		mutated[len(mutated)-backupTagBytes-2] ^= 0x80
		assertMutatedBackupRejected(t, path, mutated, provider)
	})
	t.Run("truncated final tag", func(t *testing.T) {
		assertMutatedBackupRejected(t, path, original[:len(original)-1], provider)
	})
	t.Run("trailing bytes", func(t *testing.T) {
		mutated := append(append([]byte(nil), original...), 0x01)
		assertMutatedBackupRejected(t, path, mutated, provider)
	})
	t.Run("reordered frames", func(t *testing.T) {
		mutated := reorderFirstTwoFrames(t, original)
		assertMutatedBackupRejected(t, path, mutated, provider)
	})
	t.Run("modified header", func(t *testing.T) {
		mutated := append([]byte(nil), original...)
		headerStart := len(backupMagic) + 4
		mutated[headerStart+8] ^= 0x01
		assertMutatedBackupRejected(t, path, mutated, provider)
	})
}

func FuzzBackupV5RejectsAuthenticatedByteMutations(f *testing.F) {
	ctx := context.Background()
	provider := newTestKEKProvider("fuzz-kek", 0x57)
	src, err := proofstore.OpenLocalStore(filepath.Join(f.TempDir(), "src"), cryptosuite.INTLV1, "test-node", "test-log", "fuzz-source")
	if err != nil {
		f.Fatal(err)
	}
	path := filepath.Join(f.TempDir(), "seed.tdbackup")
	if _, err := Create(ctx, src, path, testCreateOptions(provider)); err != nil {
		f.Fatal(err)
	}
	if err := src.Close(); err != nil {
		f.Fatal(err)
	}
	seed, err := os.ReadFile(path)
	if err != nil {
		f.Fatal(err)
	}
	tempDir := f.TempDir()
	f.Add(uint32(0), byte(1), uint16(0))
	f.Add(uint32(len(seed)/2), byte(0x80), uint16(1))
	f.Fuzz(func(t *testing.T, offset uint32, mask byte, truncate uint16) {
		mutated := append([]byte(nil), seed...)
		mutated[int(offset%uint32(len(mutated)))] ^= mask | 1
		if remove := int(truncate) % len(mutated); remove > 0 {
			mutated = mutated[:len(mutated)-remove]
		}
		mutatedPath, err := os.CreateTemp(tempDir, "mutation-*.tdbackup")
		if err != nil {
			t.Fatal(err)
		}
		name := mutatedPath.Name()
		if _, err := mutatedPath.Write(mutated); err != nil {
			_ = mutatedPath.Close()
			t.Fatal(err)
		}
		if err := mutatedPath.Close(); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(name)
		if _, err := Verify(ctx, name, provider); err == nil {
			t.Fatal("authenticated byte mutation was accepted")
		}
	})
}

func TestRestoreRejectsCorruptionBeforePublishingAnyEntry(t *testing.T) {
	ctx := context.Background()
	provider := newTestKEKProvider("test-kek", 0x61)
	path := createLargeTestBackup(t, provider)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-backupTagBytes-1] ^= 0x40
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	dst := newBoundTestLocalStore(t, filepath.Join(t.TempDir(), "dst"))
	_, err = RestoreWithOptions(ctx, dst, path, RestoreOptions{KEKProviders: []keyenvelope.KEKProvider{provider}})
	assertDataLoss(t, err)
	if empty, emptyErr := restoreDestinationEmpty(ctx, dst); emptyErr != nil || !empty {
		t.Fatalf("destination changed before verification completed: empty=%v err=%v", empty, emptyErr)
	}
}

func TestRestoreRequiresExactEmptyNamespace(t *testing.T) {
	ctx := context.Background()
	provider := newTestKEKProvider("test-kek", 0x71)
	src := newBoundTestLocalStore(t, filepath.Join(t.TempDir(), "src"))
	seedBackupStore(t, src, cryptosuite.INTLV1, 1, 0)
	path := filepath.Join(t.TempDir(), "proofstore.tdbackup")
	if _, err := Create(ctx, src, path, testCreateOptions(provider)); err != nil {
		t.Fatal(err)
	}

	t.Run("new namespace", func(t *testing.T) {
		dst, err := proofstore.OpenLocalStore(filepath.Join(t.TempDir(), "dst"), cryptosuite.INTLV1, "test-node", "test-log", "different")
		if err != nil {
			t.Fatal(err)
		}
		defer dst.Close()
		if _, err = RestoreWithOptions(ctx, *dst, path, RestoreOptions{KEKProviders: []keyenvelope.KEKProvider{provider}}); err != nil {
			t.Fatalf("restore into new namespace: %v", err)
		}
		if _, err := dst.GetBundle(ctx, "record-000"); err != nil {
			t.Fatalf("restored bundle: %v", err)
		}
	})

	t.Run("different log identity", func(t *testing.T) {
		dst, err := proofstore.OpenLocalStore(filepath.Join(t.TempDir(), "dst"), cryptosuite.INTLV1, "test-node", "different-log", "different")
		if err != nil {
			t.Fatal(err)
		}
		defer dst.Close()
		_, err = RestoreWithOptions(ctx, *dst, path, RestoreOptions{KEKProviders: []keyenvelope.KEKProvider{provider}})
		if trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition || !strings.Contains(err.Error(), "namespace") {
			t.Fatalf("error=%v code=%s", err, trusterr.CodeOf(err))
		}
	})

	t.Run("different cryptographic suite", func(t *testing.T) {
		dst, err := proofstore.OpenLocalStore(filepath.Join(t.TempDir(), "dst"), cryptosuite.CNSMV1, "test-node", "test-log", "different")
		if err != nil {
			t.Fatal(err)
		}
		defer dst.Close()
		_, err = RestoreWithOptions(ctx, *dst, path, RestoreOptions{KEKProviders: []keyenvelope.KEKProvider{provider}})
		if trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("error=%v code=%s", err, trusterr.CodeOf(err))
		}
	})

	t.Run("non-empty destination", func(t *testing.T) {
		dst := newBoundTestLocalStore(t, filepath.Join(t.TempDir(), "dst"))
		seedBackupStore(t, dst, cryptosuite.INTLV1, 1, 0)
		_, err := RestoreWithOptions(ctx, dst, path, RestoreOptions{KEKProviders: []keyenvelope.KEKProvider{provider}})
		if trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition || !strings.Contains(err.Error(), "not empty") {
			t.Fatalf("error=%v code=%s", err, trusterr.CodeOf(err))
		}
	})
}

func TestRestoreResumesAfterManifestWriteFailure(t *testing.T) {
	ctx := context.Background()
	provider := newTestKEKProvider("test-kek", 0x72)
	src := newBoundTestLocalStore(t, filepath.Join(t.TempDir(), "src"))
	seedBackupStore(t, src, cryptosuite.INTLV1, 3, 0)
	path := filepath.Join(t.TempDir(), "proofstore.tdbackup")
	if _, err := Create(ctx, src, path, testCreateOptions(provider)); err != nil {
		t.Fatal(err)
	}
	dst := newBoundTestLocalStore(t, filepath.Join(t.TempDir(), "dst"))
	checkpoint := filepath.Join(t.TempDir(), "restore.json")
	failing := &failManifestStore{LocalStore: dst, remaining: 1}
	_, err := RestoreWithOptions(ctx, failing, path, RestoreOptions{
		Resume: true, CheckpointPath: checkpoint, KEKProviders: []keyenvelope.KEKProvider{provider},
	})
	if err == nil || !strings.Contains(err.Error(), "injected manifest failure") {
		t.Fatalf("first restore error=%v", err)
	}
	cp, err := readRestoreCheckpoint(checkpoint)
	if err != nil || cp.BackupID == "" || cp.LastOrdinal == 0 {
		t.Fatalf("checkpoint=%+v err=%v", cp, err)
	}
	if _, err := RestoreWithOptions(ctx, dst, path, RestoreOptions{
		Resume: true, CheckpointPath: checkpoint, KEKProviders: []keyenvelope.KEKProvider{provider},
	}); err != nil {
		t.Fatalf("resumed restore: %v", err)
	}
	if _, err := dst.GetManifest(ctx, "batch-001"); err != nil {
		t.Fatalf("manifest not restored: %v", err)
	}
	leaves, err := dst.ListBatchTreeLeaves(ctx, model.BatchTreeLeafListOptions{BatchID: "batch-001", Limit: 10})
	if err != nil || len(leaves) != 3 {
		t.Fatalf("resumed batch tree leaves=%d err=%v", len(leaves), err)
	}
}

func TestBackupV5RejectsLegacyAndUnknownArchiveEntries(t *testing.T) {
	ctx := context.Background()
	provider := newTestKEKProvider("test-kek", 0x81)

	t.Run("v4/plain tar", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "legacy.tdbackup")
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		tw := tar.NewWriter(file)
		if err := writeBytes(tw, "manifest.json", []byte(`{"schema_version":"trustdb.backup.v4"}`)); err != nil {
			t.Fatal(err)
		}
		_ = tw.Close()
		_ = file.Close()
		_, err = Verify(ctx, path, provider)
		if trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition || !strings.Contains(err.Error(), "v5") {
			t.Fatalf("error=%v code=%s", err, trusterr.CodeOf(err))
		}
	})

	t.Run("unknown encrypted entry", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "unknown.tdbackup")
		writeCustomArchive(t, path, provider, func(tw *tar.Writer, manifest *Manifest, ordinal *int64) {
			if err := writeBytesTracked(tw, manifest, ordinal, "unknown/object.cbor", "unknown_type", []byte{0xf6}); err != nil {
				t.Fatal(err)
			}
		})
		_, err := Verify(ctx, path, provider)
		assertDataLoss(t, err)
	})

	t.Run("entry after manifest", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "after-manifest.tdbackup")
		writeCustomArchive(t, path, provider, func(tw *tar.Writer, manifest *Manifest, ordinal *int64) {
			if err := writeCBOR(tw, "manifest.tdmanifest", *manifest); err != nil {
				t.Fatal(err)
			}
			if err := writeBytesTracked(tw, manifest, ordinal, "roots/late.tdroot", "batch_root", []byte{0xf6}); err != nil {
				t.Fatal(err)
			}
		})
		_, err := Verify(ctx, path, provider)
		assertDataLoss(t, err)
	})

	t.Run("manifest identity substitution", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "manifest-substitution.tdbackup")
		writeCustomArchive(t, path, provider, func(tw *tar.Writer, manifest *Manifest, _ *int64) {
			manifest.BackupID = "substituted-backup-id"
			if err := writeCBOR(tw, "manifest.tdmanifest", *manifest); err != nil {
				t.Fatal(err)
			}
		})
		_, err := Verify(ctx, path, provider)
		assertDataLoss(t, err)
	})
}

func TestBackupV5StreamsLargeArchive(t *testing.T) {
	ctx := context.Background()
	provider := newTestKEKProvider("test-kek", 0x83)
	src := newBoundTestLocalStore(t, filepath.Join(t.TempDir(), "src"))
	seedBackupStore(t, src, cryptosuite.INTLV1, 8, 1<<20)
	path := filepath.Join(t.TempDir(), "large.tdbackup")
	opts := testCreateOptions(provider)
	opts.FrameBytes = minFramePlainBytes
	report, err := Create(ctx, src, path, opts)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if report.Bundles != 8 {
		t.Fatalf("bundle count=%d", report.Bundles)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() < 8<<20 {
		t.Fatalf("large archive size=%d", info.Size())
	}
	dst := openBoundTestStore(t, proofstore.BackendPebble, filepath.Join(t.TempDir(), "dst"), "large-target")
	if _, err := RestoreWithOptions(ctx, dst, path, RestoreOptions{
		KEKProviders: []keyenvelope.KEKProvider{provider},
	}); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if _, err := dst.GetBundle(ctx, "record-007"); err != nil {
		t.Fatalf("restored bundle: %v", err)
	}
}

func seedBackupStore(t *testing.T, store proofstore.Store, suiteID cryptosuite.ID, records int, padding int) {
	t.Helper()
	ctx := context.Background()
	recordIDs := make([]string, records)
	leaves := make([]model.BatchTreeLeaf, records)
	for i := 0; i < records; i++ {
		recordID := fmt.Sprintf("record-%03d", i)
		recordIDs[i] = recordID
		bundle := model.ProofBundle{
			SchemaVersion: model.SchemaProofBundle, CryptoSuite: suiteID,
			RecordID: recordID, NodeID: "test-node", LogID: "test-log",
			SignedClaim: model.SignedClaim{
				SchemaVersion: model.SchemaSignedClaim, CryptoSuite: suiteID,
				Claim: model.ClientClaim{
					SchemaVersion: model.SchemaClientClaim, CryptoSuite: suiteID,
					TenantID: "tenant", ClientID: "client", KeyID: "client-key",
					Content: model.Content{StorageURI: strings.Repeat("x", padding)},
				},
			},
			ServerRecord:    model.ServerRecord{SchemaVersion: model.SchemaServerRecord, CryptoSuite: suiteID, RecordID: recordID},
			AcceptedReceipt: model.AcceptedReceipt{SchemaVersion: model.SchemaAcceptedReceipt, CryptoSuite: suiteID, RecordID: recordID},
			CommittedReceipt: model.CommittedReceipt{
				SchemaVersion: model.SchemaCommittedReceipt, CryptoSuite: suiteID, RecordID: recordID,
				BatchID: "batch-001", LeafIndex: uint64(i), BatchRoot: repeatByte(0x44, 32), ClosedAtUnixN: 10,
			},
			BatchProof: model.BatchProof{TreeSize: uint64(records)},
		}
		if err := store.PutBundle(ctx, bundle); err != nil {
			t.Fatalf("PutBundle(%s): %v", recordID, err)
		}
		leaves[i] = model.BatchTreeLeaf{
			SchemaVersion: model.SchemaBatchTreeLeaf, CryptoSuite: suiteID, BatchID: "batch-001",
			RecordID: recordID, LeafIndex: uint64(i), LeafHash: repeatByte(byte(i+1), 32), CreatedAtUnixN: 10,
		}
	}
	nodes := []model.BatchTreeNode{{
		SchemaVersion: model.SchemaBatchTreeNode, CryptoSuite: suiteID, BatchID: "batch-001",
		Level: 1, StartIndex: 0, Width: uint64(records), Hash: repeatByte(0x44, 32), CreatedAtUnixN: 10,
	}}
	if err := store.PutBatchTreeArtifacts(ctx, leaves, nodes); err != nil {
		t.Fatalf("PutBatchTreeArtifacts: %v", err)
	}
	root := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot, CryptoSuite: suiteID, BatchID: "batch-001",
		NodeID: "test-node", LogID: "test-log", BatchRoot: repeatByte(0x44, 32), TreeSize: uint64(records), ClosedAtUnixN: 10,
	}
	if err := store.PutRoot(ctx, root); err != nil {
		t.Fatalf("PutRoot: %v", err)
	}
	if err := store.PutManifest(ctx, model.BatchManifest{
		SchemaVersion: model.SchemaBatchManifest, CryptoSuite: suiteID, BatchID: root.BatchID,
		NodeID: root.NodeID, LogID: root.LogID, State: model.BatchStateCommitted,
		TreeSize: root.TreeSize, BatchRoot: root.BatchRoot, RecordIDs: recordIDs, ClosedAtUnixN: root.ClosedAtUnixN,
	}); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
}

func openBoundTestStore(t *testing.T, kind proofstore.Backend, path, namespaceID string) proofstore.Store {
	t.Helper()
	store, err := proofstore.Open(proofstore.Config{
		Kind: kind, Path: path, CryptoSuite: cryptosuite.INTLV1,
		NodeID: "test-node", LogID: "test-log", NamespaceID: namespaceID,
	})
	if err != nil {
		t.Fatalf("open %s proofstore: %v", kind, err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close %s proofstore: %v", kind, err)
		}
	})
	return store
}

func createTestKeyRegistry(t *testing.T, path string) {
	t.Helper()
	registryPublic, registryPrivate, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	registrySigner := trustcrypto.MustNewEd25519Signer("registry-test", registryPrivate)
	registryTrust := trustcrypto.MustNewEd25519PublicKey("registry-test", registryPublic)
	registry, err := keystore.Open(path, registrySigner, registryTrust)
	if err != nil {
		t.Fatalf("open key registry: %v", err)
	}
	clientPublic, _, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	descriptor := keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindVerifier,
		Provider:      keydescriptor.ProviderPublic,
		CryptoSuite:   cryptosuite.INTLV1,
		KeyID:         "client-test",
		Algorithm:     cryptosuite.SignatureEd25519,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: cryptosuite.Ed25519PublicKeyEncoding,
			Bytes:    clientPublic,
		},
	}
	validFrom := time.Unix(100, 0).UTC()
	if _, err := registry.RegisterClientKey("tenant", "client", descriptor, validFrom, validFrom.Add(time.Hour)); err != nil {
		t.Fatalf("register client key: %v", err)
	}
}

func createLargeTestBackup(t *testing.T, provider keyenvelope.KEKProvider) string {
	t.Helper()
	src := newBoundTestLocalStore(t, filepath.Join(t.TempDir(), "src"))
	seedBackupStore(t, src, cryptosuite.INTLV1, 1, 192<<10)
	path := filepath.Join(t.TempDir(), "large.tdbackup")
	opts := testCreateOptions(provider)
	opts.FrameBytes = minFramePlainBytes
	if _, err := Create(context.Background(), src, path, opts); err != nil {
		t.Fatalf("Create large backup: %v", err)
	}
	return path
}

func testCreateOptions(provider keyenvelope.KEKProvider) Options {
	return Options{Compression: "none", KEKProvider: provider, KEKKeyID: "test-backup-kek"}
}

func assertMutatedBackupRejected(t *testing.T, originalPath string, data []byte, provider keyenvelope.KEKProvider) {
	t.Helper()
	path := filepath.Join(t.TempDir(), filepath.Base(originalPath))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Verify(context.Background(), path, provider)
	assertDataLoss(t, err)
}

func assertDataLoss(t *testing.T, err error) {
	t.Helper()
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("error=%v code=%s, want data_loss", err, trusterr.CodeOf(err))
	}
}

func reorderFirstTwoFrames(t *testing.T, archive []byte) []byte {
	t.Helper()
	if len(archive) < len(backupMagic)+4 {
		t.Fatal("archive too short")
	}
	headerLength := int(binary.BigEndian.Uint32(archive[len(backupMagic) : len(backupMagic)+4]))
	start := len(backupMagic) + 4 + headerLength
	frameEnd := func(offset int) int {
		if offset+backupFrameHeaderBytes > len(archive) {
			t.Fatal("frame header truncated")
		}
		plain := int(binary.BigEndian.Uint32(archive[offset+4 : offset+8]))
		return offset + backupFrameHeaderBytes + plain + backupTagBytes
	}
	firstEnd := frameEnd(start)
	secondEnd := frameEnd(firstEnd)
	if secondEnd > len(archive) {
		t.Fatal("archive has fewer than two frames")
	}
	out := make([]byte, 0, len(archive))
	out = append(out, archive[:start]...)
	out = append(out, archive[firstEnd:secondEnd]...)
	out = append(out, archive[start:firstEnd]...)
	out = append(out, archive[secondEnd:]...)
	return out
}

func writeCustomArchive(t *testing.T, path string, provider keyenvelope.KEKProvider, write func(*tar.Writer, *Manifest, *int64)) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	header := EnvelopeHeader{
		BackupID: "custom-backup", CreatedAt: time.Unix(1, 0).UTC().Format(time.RFC3339Nano),
		Compression: "none", CryptoSuite: cryptosuite.INTLV1, FormatGeneration: 5,
		NodeID: "test-node", LogID: "test-log", NamespaceID: "test-local",
		FramePlaintextBytes: minFramePlainBytes, KEKKeyID: "test-backup-kek",
	}
	frames, envelope, err := newEncryptedArchiveWriter(context.Background(), file, header, provider, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(frames)
	manifest := Manifest{
		SchemaVersion: SchemaManifest, BackupID: envelope.BackupID, CreatedAt: envelope.CreatedAt,
		Compression: envelope.Compression, CryptoSuite: envelope.CryptoSuite, FormatGeneration: envelope.FormatGeneration,
		NodeID: envelope.NodeID, LogID: envelope.LogID, NamespaceID: envelope.NamespaceID,
		Encryption: envelope.ContentAlgorithm, KEKProvider: envelope.KEKProvider, KEKKeyID: envelope.KEKKeyID,
		DigestAlgorithm: cryptosuite.HashSHA256, Entries: make([]Entry, 0),
	}
	var ordinal int64
	write(tw, &manifest, &ordinal)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := frames.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

type failManifestStore struct {
	proofstore.LocalStore
	remaining int
}

func (s *failManifestStore) PutManifest(ctx context.Context, manifest model.BatchManifest) error {
	if s.remaining > 0 {
		s.remaining--
		return errors.New("injected manifest failure")
	}
	return s.LocalStore.PutManifest(ctx, manifest)
}

type testKEKProvider struct {
	name string
	key  []byte
}

func newTestKEKProvider(name string, fill byte) *testKEKProvider {
	return &testKEKProvider{name: name, key: repeatByte(fill, 16)}
}

func (p *testKEKProvider) Name() string { return p.name }

func (p *testKEKProvider) WrapDEK(_ context.Context, dek, aad []byte) (keyenvelope.WrappedDEK, error) {
	aead, err := testWrapAEAD(p.key)
	if err != nil {
		return keyenvelope.WrappedDEK{}, err
	}
	nonce := repeatByte(0xa5, aead.NonceSize())
	return keyenvelope.WrappedDEK{
		Provider: p.name, Algorithm: "AES-GCM-TEST-ONLY", Parameters: nonce,
		Ciphertext: aead.Seal(nil, nonce, dek, aad),
	}, nil
}

func (p *testKEKProvider) UnwrapDEK(_ context.Context, wrapped keyenvelope.WrappedDEK, aad []byte) ([]byte, error) {
	if wrapped.Provider != p.name || wrapped.Algorithm != "AES-GCM-TEST-ONLY" {
		return nil, errors.New("test KEK metadata mismatch")
	}
	aead, err := testWrapAEAD(p.key)
	if err != nil {
		return nil, err
	}
	if len(wrapped.Parameters) != aead.NonceSize() {
		return nil, errors.New("test KEK nonce mismatch")
	}
	return aead.Open(nil, wrapped.Parameters, wrapped.Ciphertext, aad)
}

func testWrapAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func testSTH(key model.STHAnchorScheduleKey, treeSize uint64, fill byte) model.SignedTreeHead {
	return model.SignedTreeHead{
		SchemaVersion: model.SchemaSignedTreeHead, CryptoSuite: cryptosuite.INTLV1,
		NodeID: key.NodeID, LogID: key.LogID, TreeAlg: cryptosuite.MerkleRFC6962SHA256, TreeSize: treeSize, RootHash: repeatByte(fill, 32),
		TimestampUnixN: 1,
		Signature:      model.Signature{Alg: cryptosuite.SignatureEd25519, KeyID: "server-key", Signature: repeatByte(0x99, 64)},
	}
}

func repeatByte(value byte, count int) []byte { return bytes.Repeat([]byte{value}, count) }

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

var _ io.Reader = (*bytes.Reader)(nil)
