package main

import (
	"path/filepath"
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/wal"
)

func TestBindWALNamespaceOptionsUsesServeLogFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal")
	opts, absolutePath, err := bindWALNamespaceOptions(wal.Options{}, cryptosuite.INTLV1, "node-a", "", path)
	if err != nil {
		t.Fatal(err)
	}
	if opts.LogID != "node-a" || opts.NodeID != "node-a" || opts.NamespaceID != "wal:"+absolutePath {
		t.Fatalf("binding options=%+v absolute=%q", opts, absolutePath)
	}
	writer, err := wal.OpenDirWriter(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := wal.ReadAllDir(path, opts); err != nil {
		t.Fatalf("read fallback-bound WAL: %v", err)
	}
	for _, wrong := range []wal.Options{
		{CryptoSuite: cryptosuite.CNSMV1, NodeID: opts.NodeID, LogID: opts.LogID, NamespaceID: opts.NamespaceID},
		{CryptoSuite: opts.CryptoSuite, NodeID: "node-b", LogID: opts.LogID, NamespaceID: opts.NamespaceID},
		{CryptoSuite: opts.CryptoSuite, NodeID: opts.NodeID, LogID: opts.LogID, NamespaceID: "wal:other"},
	} {
		if _, err := wal.ReadAllDir(path, wrong); err == nil {
			t.Fatalf("reader accepted wrong binding %+v", wrong)
		}
	}
}
