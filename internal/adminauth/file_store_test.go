package adminauth

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestFileStoreBootstrapReplaceAndHistory(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "admin-policy.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(t)
	digest, err := store.Bootstrap(policy, testNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Bootstrap(policy, testNow()); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second Bootstrap() error = %v", err)
	}
	loaded, loadedDigest, err := store.Load(testNow())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != 1 || loadedDigest != digest {
		t.Fatalf("Load() version=%d digest=%s", loaded.Version, loadedDigest)
	}
	manager, err := NewManager(policy, testNow())
	if err != nil {
		t.Fatal(err)
	}
	actor, err := manager.AuthenticateLocal("security", "correct horse battery staple", testNow())
	if err != nil {
		t.Fatal(err)
	}
	next := policy.Clone()
	next.Version++
	next.Accounts = append(next.Accounts, Account{})
	copy(next.Accounts[3:], next.Accounts[2:])
	next.Accounts[2] = Account{
		ID: "support", Username: "support", PasswordHash: policy.Accounts[0].PasswordHash,
		Roles: []Role{RoleSupportReadOnly}, SessionEpoch: 1,
	}
	nextDigest, err := store.ReplaceOnline(actor, digest, next, testNow())
	if err != nil {
		t.Fatal(err)
	}
	loaded, loadedDigest, err = store.Load(testNow())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != 2 || loadedDigest != nextDigest {
		t.Fatalf("Load() version=%d digest=%s", loaded.Version, loadedDigest)
	}
	history, err := filepath.Glob(path + ".history/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || !strings.Contains(filepath.Base(history[0]), digest) {
		t.Fatalf("history = %v", history)
	}
}

func TestFileStoreRejectsStaleDigest(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "admin-policy.json")
	store, _ := NewFileStore(path)
	policy := testPolicy(t)
	if _, err := store.Bootstrap(policy, testNow()); err != nil {
		t.Fatal(err)
	}
	next := policy.Clone()
	next.Version++
	if _, err := store.ReplaceOffline(strings.Repeat("0", 64), next, testNow()); !errors.Is(err, ErrPolicyConflict) {
		t.Fatalf("ReplaceOffline(stale) error = %v", err)
	}
}

func TestFileStoreSerializesConcurrentCASWriters(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "admin-policy.json")
	firstStore, _ := NewFileStore(path)
	secondStore, _ := NewFileStore(path)
	policy := testPolicy(t)
	digest, err := firstStore.Bootstrap(policy, testNow())
	if err != nil {
		t.Fatal(err)
	}
	firstNext := policy.Clone()
	firstNext.Version++
	firstNext.Accounts[2].Description = "first"
	secondNext := policy.Clone()
	secondNext.Version++
	secondNext.Accounts[2].Description = "second"

	start := make(chan struct{})
	errorsSeen := make(chan error, 2)
	var wait sync.WaitGroup
	for _, update := range []struct {
		store *FileStore
		next  Policy
	}{{firstStore, firstNext}, {secondStore, secondNext}} {
		wait.Add(1)
		go func(store *FileStore, next Policy) {
			defer wait.Done()
			<-start
			_, updateErr := store.ReplaceOffline(digest, next, testNow())
			errorsSeen <- updateErr
		}(update.store, update.next)
	}
	close(start)
	wait.Wait()
	close(errorsSeen)
	successes, conflicts := 0, 0
	for updateErr := range errorsSeen {
		switch {
		case updateErr == nil:
			successes++
		case errors.Is(updateErr, ErrPolicyConflict):
			conflicts++
		default:
			t.Fatalf("concurrent update error=%v", updateErr)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestFileStoreRejectsUnsafeTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not generally available to unprivileged Windows tests")
	}
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("not a policy"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "admin-policy.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	store, _ := NewFileStore(path)
	if _, _, err := store.Load(testNow()); !errors.Is(err, ErrUnsafeStorage) {
		t.Fatalf("Load(symlink) error = %v", err)
	}
}
