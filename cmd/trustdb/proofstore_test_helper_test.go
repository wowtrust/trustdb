package main

import (
	"path/filepath"
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/proofstore"
	"github.com/wowtrust/trustdb/v2/internal/wal"
)

func newBoundTestLocalStore(t testing.TB, root string) proofstore.LocalStore {
	return newBoundTestLocalStoreForSuite(t, root, cryptosuite.INTLV1)
}

func newBoundTestWALOptions(t testing.TB, path string, opts wal.Options) wal.Options {
	t.Helper()
	absolutePath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		t.Fatalf("resolve test WAL namespace: %v", err)
	}
	opts.CryptoSuite = cryptosuite.INTLV1
	opts.NodeID = "local-server"
	opts.LogID = "trustdb-global-log"
	opts.NamespaceID = "wal:" + absolutePath
	return opts
}

func openBoundTestWALWriter(t testing.TB, path string, maxSegmentBytes int64) (*wal.Writer, string, error) {
	t.Helper()
	return openWALWriterWithOptions(path, newBoundTestWALOptions(t, path, wal.Options{MaxSegmentBytes: maxSegmentBytes}))
}

func newBoundTestLocalStoreForSuite(t testing.TB, root string, suiteID cryptosuite.ID) proofstore.LocalStore {
	t.Helper()
	store, err := proofstore.OpenLocalStore(root, suiteID, "local-server", "trustdb-global-log", proofstoreNamespaceID("file", root, "", ""))
	if err != nil {
		t.Fatalf("open test local proofstore: %v", err)
	}
	return *store
}

func newBoundTestProofstoreConfig(kind proofstore.Backend, path string) proofstore.Config {
	return proofstore.Config{
		Kind:        kind,
		Path:        path,
		CryptoSuite: cryptosuite.INTLV1,
		NodeID:      "local-server",
		LogID:       "trustdb-global-log",
		NamespaceID: proofstoreNamespaceID(string(kind), path, "", ""),
	}
}
