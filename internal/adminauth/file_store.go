package adminauth

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	ErrPolicyConflict = errors.New("adminauth: policy changed concurrently")
	ErrUnsafeStorage  = errors.New("adminauth: unsafe policy storage")
)

// FileStore persists the current policy and immutable predecessor revisions.
// It serializes changes made by this process; the digest check also fails
// closed when another process replaced the policy between operations.
type FileStore struct {
	path string
	mu   sync.Mutex
}

func NewFileStore(path string) (*FileStore, error) {
	clean := filepath.Clean(path)
	if path == "" || clean == "." || filepath.Base(clean) == "." {
		return nil, errors.New("adminauth: policy path is required")
	}
	return &FileStore{path: clean}, nil
}

func (s *FileStore) Path() string { return s.path }

func (s *FileStore) Load(now time.Time) (Policy, string, error) {
	data, err := readSecurePolicyFile(s.path)
	if err != nil {
		return Policy{}, "", err
	}
	policy, err := ParsePolicy(data, now)
	if err != nil {
		return Policy{}, "", err
	}
	digest, err := policy.Digest()
	if err != nil {
		return Policy{}, "", err
	}
	return policy, digest, nil
}

// Bootstrap installs the first policy. It never replaces an existing path.
func (s *FileStore) Bootstrap(policy Policy, now time.Time) (digest string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := acquirePolicyFileLock(s.path)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, release()) }()
	if err := policy.Validate(now); err != nil {
		return "", err
	}
	if policy.Version != 1 {
		return "", errors.New("adminauth: bootstrap policy version must be 1")
	}
	data, err := policy.CanonicalBytes()
	if err != nil {
		return "", err
	}
	if err := writePolicyAtomic(s.path, data, false); err != nil {
		return "", err
	}
	return policy.Digest()
}

// ReplaceOnline checks actor separation rules, archives the current revision,
// then atomically installs the next one.
func (s *FileStore) ReplaceOnline(actor Principal, expectedDigest string, next Policy, now time.Time) (nextDigest string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := acquirePolicyFileLock(s.path)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, release()) }()
	current, digest, err := s.loadLocked(now)
	if err != nil {
		return "", err
	}
	if expectedDigest == "" || expectedDigest != digest {
		return "", ErrPolicyConflict
	}
	if err := ValidateOnlineUpdate(actor, current, next, now); err != nil {
		return "", err
	}
	return s.replaceLocked(current, digest, next)
}

// ReplaceOffline is the explicit recovery path. It preserves history and CAS,
// but deliberately does not apply online actor/self/emergency restrictions.
func (s *FileStore) ReplaceOffline(expectedDigest string, next Policy, now time.Time) (nextDigest string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := acquirePolicyFileLock(s.path)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, release()) }()
	current, digest, err := s.loadLocked(now)
	if err != nil {
		return "", err
	}
	if expectedDigest == "" || expectedDigest != digest {
		return "", ErrPolicyConflict
	}
	if err := next.Validate(now); err != nil {
		return "", err
	}
	if next.Version != current.Version+1 {
		return "", errors.New("adminauth: replacement policy version must advance by exactly one")
	}
	return s.replaceLocked(current, digest, next)
}

func (s *FileStore) loadLocked(now time.Time) (Policy, string, error) {
	data, err := readSecurePolicyFile(s.path)
	if err != nil {
		return Policy{}, "", err
	}
	policy, err := ParsePolicy(data, now)
	if err != nil {
		return Policy{}, "", err
	}
	digest, err := policy.Digest()
	return policy, digest, err
}

func (s *FileStore) replaceLocked(current Policy, currentDigest string, next Policy) (string, error) {
	currentData, err := current.CanonicalBytes()
	if err != nil {
		return "", err
	}
	if err := writePolicyHistory(s.path, current.Version, currentDigest, currentData); err != nil {
		return "", err
	}
	nextData, err := next.CanonicalBytes()
	if err != nil {
		return "", err
	}
	if err := writePolicyAtomic(s.path, nextData, true); err != nil {
		return "", err
	}
	return next.Digest()
}

func readSecurePolicyFile(path string) ([]byte, error) {
	data, err := ReadOwnerOnlyFile(path, MaxPolicyBytes)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("adminauth: policy size must be between 1 and %d bytes", MaxPolicyBytes)
	}
	return data, nil
}

// ReadOwnerOnlyFile reads a bounded regular file after proving stable identity,
// current-user ownership, and owner-only access on the host platform.
func ReadOwnerOnlyFile(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("adminauth: maximum file size must be positive")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: policy target is not a regular file", ErrUnsafeStorage)
	}
	if err := validatePolicyFilePermissions(path, before); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) || !after.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: policy target changed while opening", ErrUnsafeStorage)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("adminauth: owner-only file exceeds %d bytes", maxBytes)
	}
	return data, nil
}

func writePolicyHistory(policyPath string, version uint64, digest string, data []byte) error {
	dir := policyPath + ".history"
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: policy history is not a directory", ErrUnsafeStorage)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	} else if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	name := fmt.Sprintf("v%020d-%s.json", version, digest)
	historyPath := filepath.Join(dir, name)
	if err := writePolicyAtomic(historyPath, data, false); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
		existing, readErr := readSecurePolicyFile(historyPath)
		if readErr != nil || string(existing) != string(data) {
			return fmt.Errorf("%w: conflicting policy history revision", ErrUnsafeStorage)
		}
	}
	return nil
}

func writePolicyAtomic(path string, data []byte, replace bool) error {
	if len(data) == 0 || len(data) > MaxPolicyBytes {
		return fmt.Errorf("adminauth: policy size must be between 1 and %d bytes", MaxPolicyBytes)
	}
	dir := filepath.Dir(path)
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: policy parent is not a directory", ErrUnsafeStorage)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	} else if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: policy target is not a regular file", ErrUnsafeStorage)
		}
		if !replace {
			return fs.ErrExist
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	} else if replace {
		return fs.ErrNotExist
	}
	tmp, err := os.CreateTemp(dir, ".trustdb-admin-policy-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	closed := false
	cleanup := true
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := securePolicyFile(tmp); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		closed = true
		return err
	}
	closed = true
	if err := installPolicyFile(tmpPath, path, replace); err != nil {
		return err
	}
	cleanup = false
	return syncPolicyDirectory(dir)
}
