package wal

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
)

const (
	walLockRoleEnv    = "TRUSTDB_TEST_WAL_LOCK_ROLE"
	walLockLayoutEnv  = "TRUSTDB_TEST_WAL_LOCK_LAYOUT"
	walLockPathEnv    = "TRUSTDB_TEST_WAL_LOCK_PATH"
	walLockSuiteEnv   = "TRUSTDB_TEST_WAL_LOCK_SUITE"
	walLockNodeEnv    = "TRUSTDB_TEST_WAL_LOCK_NODE"
	walLockReadyEnv   = "TRUSTDB_TEST_WAL_LOCK_READY"
	walLockReleaseEnv = "TRUSTDB_TEST_WAL_LOCK_RELEASE"
)

func TestWALNamespaceProcessLockHelper(t *testing.T) {
	role := os.Getenv(walLockRoleEnv)
	if role == "" {
		t.Skip("subprocess helper")
	}
	path := os.Getenv(walLockPathEnv)
	opts := Options{
		CryptoSuite: cryptosuite.ID(os.Getenv(walLockSuiteEnv)),
		NodeID:      os.Getenv(walLockNodeEnv),
		LogID:       "log",
		NamespaceID: "namespace",
		FsyncMode:   FsyncBatch,
	}
	var (
		writer *Writer
		err    error
	)
	switch os.Getenv(walLockLayoutEnv) {
	case "directory":
		writer, err = OpenDirWriter(path, opts)
	case "single":
		writer, err = OpenWriterWithOptions(path, 1, opts)
	default:
		t.Fatalf("unknown layout")
	}
	switch role {
	case "holder":
		if err != nil {
			t.Fatalf("holder open: %v", err)
		}
		defer writer.Close()
		if err := os.WriteFile(os.Getenv(walLockReadyEnv), []byte("ready"), 0o600); err != nil {
			t.Fatalf("publish ready: %v", err)
		}
		waitForWALTestFile(t, os.Getenv(walLockReleaseEnv))
	case "contender":
		if err == nil {
			_ = writer.Close()
			t.Fatal("second writer unexpectedly opened")
		}
		fmt.Fprintln(os.Stdout, "rejected")
	default:
		t.Fatalf("unknown role %q", role)
	}
}

func TestWALRejectsSecondWriterProcessForDirectoryAndSingleFile(t *testing.T) {
	for _, layout := range []string{"directory", "single"} {
		for _, binding := range []struct {
			name  string
			suite cryptosuite.ID
			node  string
		}{
			{name: "same_binding", suite: cryptosuite.INTLV1, node: "node-a"},
			{name: "different_binding", suite: cryptosuite.CNSMV1, node: "node-b"},
		} {
			t.Run(layout+"/"+binding.name, func(t *testing.T) {
				base := t.TempDir()
				path := filepath.Join(base, "wal")
				if layout == "single" {
					path += ".wal"
				}
				ready := filepath.Join(t.TempDir(), "ready")
				release := filepath.Join(t.TempDir(), "release")
				holder := walLockSubprocess(t, "holder", layout, path, cryptosuite.INTLV1, "node-a", ready, release)
				if err := holder.Start(); err != nil {
					t.Fatalf("start holder: %v", err)
				}
				waitForWALTestFile(t, ready)
				output, err := walLockSubprocess(t, "contender", layout, path, binding.suite, binding.node, "", "").CombinedOutput()
				if err != nil {
					t.Fatalf("contender failed: %v\n%s", err, output)
				}
				if !strings.Contains(string(output), "rejected") {
					t.Fatalf("contender output=%q", output)
				}
				if err := os.WriteFile(release, []byte("release"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := holder.Wait(); err != nil {
					t.Fatalf("holder failed: %v", err)
				}
			})
		}
	}
}

func TestLiveDirectoryWriterAllowsSafePruneButRejectsRepair(t *testing.T) {
	dir := t.TempDir()
	opts := testWALOptions(Options{MaxSegmentBytes: 180, FsyncMode: FsyncBatch})
	writer, err := OpenDirWriter(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if second, err := OpenDirWriter(dir, opts); err == nil {
		_ = second.Close()
		t.Fatal("second in-process directory writer unexpectedly opened")
	}
	for i := 0; i < 6; i++ {
		if _, _, err := writer.Append(context.Background(), bytes.Repeat([]byte{byte(i + 1)}, 96)); err != nil {
			t.Fatal(err)
		}
	}
	active := writer.ActiveSegmentID()
	if active < 2 {
		t.Fatalf("active segment=%d, want rotation", active)
	}
	if _, _, err := PruneSegmentsBefore(dir, active+1, opts); err == nil {
		t.Fatal("prune accepted cutoff that would delete the active segment")
	}
	removed, _, err := PruneSegmentsBefore(dir, active, opts)
	if err != nil || removed == 0 {
		t.Fatalf("safe live prune removed=%d err=%v", removed, err)
	}
	if _, err := RepairDir(dir, opts); err == nil {
		t.Fatal("repair opened while directory writer was active")
	}
	if _, _, err := writer.Append(context.Background(), []byte("after-prune")); err != nil {
		t.Fatalf("append after prune: %v", err)
	}
	if _, err := ReadAllDir(dir, opts); err != nil {
		t.Fatalf("read after live prune and append: %v", err)
	}
}

func TestLiveSingleFileWriterRejectsRepairWithoutMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.wal")
	opts := testWALOptions(Options{FsyncMode: FsyncBatch})
	writer, err := OpenWriterWithOptions(path, 1, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if second, err := OpenWriterWithOptions(path, 1, opts); err == nil {
		_ = second.Close()
		t.Fatal("second in-process single-file writer unexpectedly opened")
	}
	if _, _, err := writer.Append(context.Background(), []byte("before")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Repair(path, opts); err == nil {
		t.Fatal("repair opened while single-file writer was active")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected live repair mutated single-file WAL")
	}
}

func TestNamespaceLockCloseAcquireStressDoesNotDeadlock(t *testing.T) {
	for iteration := 0; iteration < 25; iteration++ {
		dir := t.TempDir()
		opts := testWALOptions(Options{FsyncMode: FsyncBatch})
		writer, err := OpenDirWriter(dir, opts)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := writer.Append(context.Background(), []byte("record")); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		done := make(chan struct{}, 3)
		go func() {
			<-start
			_ = writer.Close()
			done <- struct{}{}
		}()
		go func() {
			<-start
			_, _ = ReadAllDir(dir, opts)
			done <- struct{}{}
		}()
		go func() {
			<-start
			_, _, _ = PruneSegmentsBefore(dir, 1, opts)
			done <- struct{}{}
		}()
		close(start)
		timeout := time.NewTimer(5 * time.Second)
		for completed := 0; completed < 3; completed++ {
			select {
			case <-done:
			case <-timeout.C:
				t.Fatalf("iteration %d deadlocked closing and acquiring namespace locks", iteration)
			}
		}
		if !timeout.Stop() {
			<-timeout.C
		}
	}
}

func walLockSubprocess(t *testing.T, role, layout, path string, suiteID cryptosuite.ID, nodeID, ready, release string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestWALNamespaceProcessLockHelper$")
	cmd.Env = append(os.Environ(),
		walLockRoleEnv+"="+role,
		walLockLayoutEnv+"="+layout,
		walLockPathEnv+"="+path,
		walLockSuiteEnv+"="+string(suiteID),
		walLockNodeEnv+"="+nodeID,
		walLockReadyEnv+"="+ready,
		walLockReleaseEnv+"="+release,
	)
	return cmd
}

func waitForWALTestFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatalf("inspect synchronization file: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
