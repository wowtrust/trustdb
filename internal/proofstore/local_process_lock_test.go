package proofstore

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/trusterr"
)

const (
	localLockRoleEnv    = "TRUSTDB_TEST_LOCAL_LOCK_ROLE"
	localLockRootEnv    = "TRUSTDB_TEST_LOCAL_LOCK_ROOT"
	localLockSuiteEnv   = "TRUSTDB_TEST_LOCAL_LOCK_SUITE"
	localLockNodeEnv    = "TRUSTDB_TEST_LOCAL_LOCK_NODE"
	localLockReadyEnv   = "TRUSTDB_TEST_LOCAL_LOCK_READY"
	localLockReleaseEnv = "TRUSTDB_TEST_LOCAL_LOCK_RELEASE"
)

func TestLocalStoreProcessLockHelper(t *testing.T) {
	role := os.Getenv(localLockRoleEnv)
	if role == "" {
		t.Skip("subprocess helper")
	}
	store, err := OpenLocalStore(
		os.Getenv(localLockRootEnv),
		cryptosuite.ID(os.Getenv(localLockSuiteEnv)),
		os.Getenv(localLockNodeEnv),
		"log",
		"namespace",
	)
	switch role {
	case "holder":
		if err != nil {
			t.Fatalf("holder open: %v", err)
		}
		defer store.Close()
		if err := os.WriteFile(os.Getenv(localLockReadyEnv), []byte("ready"), 0o600); err != nil {
			t.Fatalf("publish holder ready: %v", err)
		}
		waitForTestFile(t, os.Getenv(localLockReleaseEnv))
	case "contender":
		if trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			if err == nil {
				_ = store.Close()
			}
			t.Fatalf("contender code=%s err=%v, want failed_precondition", trusterr.CodeOf(err), err)
		}
		fmt.Fprintln(os.Stdout, "rejected")
	default:
		t.Fatalf("unknown subprocess role %q", role)
	}
}

func TestLocalStoreRejectsSecondProcessForSameAndDifferentBinding(t *testing.T) {
	for _, tc := range []struct {
		name           string
		contenderSuite cryptosuite.ID
		contenderNode  string
	}{
		{name: "same_binding", contenderSuite: cryptosuite.INTLV1, contenderNode: "node-a"},
		{name: "different_binding", contenderSuite: cryptosuite.CNSMV1, contenderNode: "node-b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "store")
			ready := filepath.Join(t.TempDir(), "ready")
			release := filepath.Join(t.TempDir(), "release")
			holder := localLockSubprocess(t, "holder", root, cryptosuite.INTLV1, "node-a", ready, release)
			if err := holder.Start(); err != nil {
				t.Fatalf("start holder: %v", err)
			}
			waitForTestFile(t, ready)

			contender := localLockSubprocess(t, "contender", root, tc.contenderSuite, tc.contenderNode, "", "")
			output, err := contender.CombinedOutput()
			if err != nil {
				t.Fatalf("contender failed: %v\n%s", err, output)
			}
			if !strings.Contains(string(output), "rejected") {
				t.Fatalf("contender output=%q, want rejection marker", output)
			}

			if err := os.WriteFile(release, []byte("release"), 0o600); err != nil {
				t.Fatalf("release holder: %v", err)
			}
			if err := holder.Wait(); err != nil {
				t.Fatalf("holder failed: %v", err)
			}

			store, err := OpenLocalStore(root, cryptosuite.INTLV1, "node-a", "log", "namespace")
			if err != nil {
				t.Fatalf("reopen after holder exit: %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatalf("close reopened store: %v", err)
			}
			if _, err := OpenLocalStore(root, cryptosuite.CNSMV1, "node-b", "log", "namespace"); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
				t.Fatalf("persistent marker mismatch code=%s err=%v", trusterr.CodeOf(err), err)
			}
		})
	}
}

func TestLocalStoreOperationsFailAfterCloseAndThroughCopy(t *testing.T) {
	store, err := OpenLocalStore(t.TempDir(), cryptosuite.INTLV1, "node", "log", "namespace")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	copied := *store
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	if _, _, err := store.GetCheckpoint(context.Background()); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("read after close code=%s err=%v, want failed_precondition", trusterr.CodeOf(err), err)
	}
	root := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		CryptoSuite:   cryptosuite.INTLV1,
		BatchID:       "batch-after-close",
		ClosedAtUnixN: 1,
	}
	if err := copied.PutRoot(context.Background(), root); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("copied writer after close code=%s err=%v, want failed_precondition", trusterr.CodeOf(err), err)
	}
	if _, err := os.Stat(copied.rootPath(root.ClosedAtUnixN, root.BatchID)); !os.IsNotExist(err) {
		t.Fatalf("closed copied writer created a root file: %v", err)
	}
}

func TestLocalStoreCloseWaitsForInFlightNestedOperation(t *testing.T) {
	store, err := OpenLocalStore(t.TempDir(), cryptosuite.INTLV1, "node", "log", "namespace")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	release, err := store.beginOperation()
	if err != nil {
		t.Fatalf("begin outer operation: %v", err)
	}

	closeResult := make(chan error, 1)
	go func() {
		closeResult <- store.Close()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !store.lock.closing.Load() {
		if time.Now().After(deadline) {
			release()
			t.Fatal("close did not enter closing state")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-closeResult:
		release()
		t.Fatalf("close returned before in-flight operation completed: %v", err)
	default:
	}

	nestedResult := make(chan error, 1)
	go func() {
		_, err := store.listSTHAnchorResultsPage(context.Background(), model.AnchorListOptions{Limit: 1})
		nestedResult <- err
	}()
	select {
	case err := <-nestedResult:
		if err != nil {
			release()
			t.Fatalf("nested no-lease helper failed while close was pending: %v", err)
		}
	case <-time.After(5 * time.Second):
		release()
		t.Fatal("nested no-lease helper deadlocked behind pending close")
	}
	release()
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("close store: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close did not finish after in-flight operation released")
	}
}

func TestLocalStoreClosedCopyCannotWriteAfterProcessTakeover(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	store, err := OpenLocalStore(root, cryptosuite.INTLV1, "node-a", "log", "namespace")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	copied := *store
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	ready := filepath.Join(t.TempDir(), "ready")
	release := filepath.Join(t.TempDir(), "release")
	holder := localLockSubprocess(t, "holder", root, cryptosuite.INTLV1, "node-a", ready, release)
	if err := holder.Start(); err != nil {
		t.Fatalf("start takeover holder: %v", err)
	}
	waitForTestFile(t, ready)

	batchRoot := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		CryptoSuite:   cryptosuite.INTLV1,
		BatchID:       "batch-after-takeover",
		ClosedAtUnixN: 2,
	}
	if err := copied.PutRoot(context.Background(), batchRoot); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("old copied writer code=%s err=%v, want failed_precondition", trusterr.CodeOf(err), err)
	}
	if _, err := os.Stat(copied.rootPath(batchRoot.ClosedAtUnixN, batchRoot.BatchID)); !os.IsNotExist(err) {
		t.Fatalf("old copied writer created a root file during process takeover: %v", err)
	}

	if err := os.WriteFile(release, []byte("release"), 0o600); err != nil {
		t.Fatalf("release takeover holder: %v", err)
	}
	if err := holder.Wait(); err != nil {
		t.Fatalf("takeover holder failed: %v", err)
	}
}

func localLockSubprocess(t *testing.T, role, root string, suiteID cryptosuite.ID, nodeID, ready, release string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLocalStoreProcessLockHelper$")
	cmd.Env = append(os.Environ(),
		localLockRoleEnv+"="+role,
		localLockRootEnv+"="+root,
		localLockSuiteEnv+"="+string(suiteID),
		localLockNodeEnv+"="+nodeID,
		localLockReadyEnv+"="+ready,
		localLockReleaseEnv+"="+release,
	)
	return cmd
}

func waitForTestFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatalf("inspect test synchronization file: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
