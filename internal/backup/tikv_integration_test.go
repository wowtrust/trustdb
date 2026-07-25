//go:build integration

package backup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keyenvelope"
	"github.com/wowtrust/trustdb/internal/proofstore"
)

func TestBackupV5TiKVPortableRestoreContract(t *testing.T) {
	pdEndpoints := splitIntegrationValues(os.Getenv("TRUSTDB_TIKV_PD_ENDPOINTS"))
	if len(pdEndpoints) == 0 {
		t.Skip("set TRUSTDB_TIKV_PD_ENDPOINTS to run the TiKV backup contract")
	}
	ctx := context.Background()
	provider := newTestKEKProvider("tikv-test-kek", 0x5b)
	localSource := openBoundTestStore(t, proofstore.BackendFile, filepath.Join(t.TempDir(), "local-src"), "local-source")
	seedBackupStore(t, localSource, cryptosuite.INTLV1, 3, 0)

	firstArchive := filepath.Join(t.TempDir(), "local-to-tikv.tdbackup")
	if _, err := Create(ctx, localSource, firstArchive, testCreateOptions(provider)); err != nil {
		t.Fatalf("create local archive: %v", err)
	}

	namespace := "backup-v5-" + time.Now().UTC().Format("20060102-150405.000000000")
	tikvStore, err := proofstore.Open(proofstore.Config{
		Kind: proofstore.BackendTiKV, TiKVPDAddresses: pdEndpoints,
		TiKVKeyspace: os.Getenv("TRUSTDB_TIKV_KEYSPACE"), TiKVNamespace: namespace,
		CryptoSuite: cryptosuite.INTLV1, NodeID: "test-node", LogID: "test-log", NamespaceID: namespace,
	})
	if err != nil {
		t.Fatalf("open TiKV proofstore: %v", err)
	}
	t.Cleanup(func() { _ = tikvStore.Close() })
	if _, err := RestoreWithOptions(ctx, tikvStore, firstArchive, RestoreOptions{
		KEKProviders: []keyenvelope.KEKProvider{provider},
	}); err != nil {
		t.Fatalf("restore local archive into TiKV: %v", err)
	}

	secondArchive := filepath.Join(t.TempDir(), "tikv-to-local.tdbackup")
	if _, err := Create(ctx, tikvStore, secondArchive, testCreateOptions(provider)); err != nil {
		t.Fatalf("create TiKV archive: %v", err)
	}
	localTarget := openBoundTestStore(t, proofstore.BackendFile, filepath.Join(t.TempDir(), "local-dst"), "local-target")
	if _, err := RestoreWithOptions(ctx, localTarget, secondArchive, RestoreOptions{
		KEKProviders: []keyenvelope.KEKProvider{provider},
	}); err != nil {
		t.Fatalf("restore TiKV archive into local proofstore: %v", err)
	}
	if _, err := localTarget.GetBundle(ctx, "record-002"); err != nil {
		t.Fatalf("restored TiKV bundle: %v", err)
	}
}

func splitIntegrationValues(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			out = append(out, value)
		}
	}
	return out
}
