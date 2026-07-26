package wal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm3"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
)

func testWALOptions(opts Options) Options {
	if opts.CryptoSuite == "" {
		opts.CryptoSuite = cryptosuite.INTLV1
	}
	if opts.NodeID == "" {
		opts.NodeID = "test-node"
	}
	if opts.LogID == "" {
		opts.LogID = "test-log"
	}
	if opts.NamespaceID == "" {
		opts.NamespaceID = "test-wal"
	}
	return opts
}

func writeTestDirBinding(t *testing.T, dir string, opts Options) {
	t.Helper()
	binding, err := bindingForOptions(testWALOptions(opts))
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureBinding(filepath.Join(dir, bindingFileName), binding, false, defaultWALFileOps()); err != nil {
		t.Fatalf("write test WAL binding: %v", err)
	}
}

func writeTestSingleBinding(t *testing.T, path string, opts Options) {
	t.Helper()
	binding, err := bindingForOptions(testWALOptions(opts))
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureBinding(path+".binding", binding, false, defaultWALFileOps()); err != nil {
		t.Fatalf("write test single-file WAL binding: %v", err)
	}
}

func TestBindingPublicationRecoversAtCrashBoundaries(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("injected binding failure")
	for _, tc := range []struct {
		name   string
		inject func(*walFileOps)
	}{
		{name: "file sync", inject: func(ops *walFileOps) {
			ops.syncFile = func(*os.File) error { return sentinel }
		}},
		{name: "close", inject: func(ops *walFileOps) {
			ops.closeFile = func(file *os.File) error {
				_ = file.Close()
				return sentinel
			}
		}},
		{name: "rename", inject: func(ops *walFileOps) {
			ops.replace = func(string, string) error { return sentinel }
		}},
		{name: "directory sync after rename", inject: func(ops *walFileOps) {
			ops.syncDir = func(string) error { return sentinel }
		}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, bindingFileName)
			expected, err := bindingForOptions(testWALOptions(Options{}))
			if err != nil {
				t.Fatal(err)
			}
			ops := defaultWALFileOps()
			tc.inject(&ops)
			if err := ensureBinding(path, expected, false, ops); !errors.Is(err, sentinel) {
				t.Fatalf("ensureBinding() error = %v, want sentinel", err)
			}
			if err := ensureBinding(path, expected, false, defaultWALFileOps()); err != nil {
				t.Fatalf("retry ensureBinding() error = %v", err)
			}
			if _, err := os.Stat(path + bindingTempSuffix); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("orphan binding temp remains: %v", err)
			}
		})
	}
}

func TestBindingRejectsIdentityReuseBeforeSegmentScan(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first := testWALOptions(Options{})
	writer, err := OpenDirWriter(dir, first)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	second := first
	second.LogID = "other-log"
	if _, err := OpenDirWriter(dir, second); err == nil || !strings.Contains(err.Error(), "namespace binding mismatch") {
		t.Fatalf("OpenDirWriter() identity mismatch error = %v", err)
	}
}

func TestCNSMV1RecordHashChainUsesSM3(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "records.wal")
	opts := testWALOptions(Options{CryptoSuite: cryptosuite.CNSMV1})
	writer, err := OpenWriterWithOptions(path, 1, opts)
	if err != nil {
		t.Fatal(err)
	}
	_, recordHash, err := writer.Append(context.Background(), []byte("sm3-wal"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < recordHashSize {
		t.Fatalf("WAL record size = %d", len(data))
	}
	want := sm3.Sum(data[:len(data)-recordHashSize])
	if !bytes.Equal(recordHash[:], want[:]) {
		t.Fatalf("record hash = %x, want SM3 %x", recordHash, want)
	}
}
