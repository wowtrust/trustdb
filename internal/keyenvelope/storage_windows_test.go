//go:build windows

package keyenvelope

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsEnvelopeStorageCreateReadUpdateDeleteContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.material")
	provider := testPassphraseProvider("windows contract passphrase")
	first, err := sealWithRand(
		context.Background(),
		testMetadata,
		bytes.Repeat([]byte{0x41}, 64),
		provider,
		deterministicReader(41),
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sealWithRand(
		context.Background(),
		testMetadata,
		bytes.Repeat([]byte{0x42}, 64),
		provider,
		deterministicReader(42),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := WriteFile(path, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, second); !errors.Is(err, os.ErrExist) {
		t.Fatalf("duplicate WriteFile error = %v, want os.ErrExist", err)
	}
	got, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Fatal("ReadFile did not return the installed envelope")
	}
	if err := UpdateFile(context.Background(), path, func(current []byte) ([]byte, error) {
		if !bytes.Equal(current, first) {
			t.Fatal("UpdateFile did not read the current durable envelope")
		}
		return append([]byte(nil), second...), nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err = ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, second) {
		t.Fatal("UpdateFile did not atomically replace the envelope")
	}
	if err := RemoveFile(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadFile after RemoveFile error = %v, want os.ErrNotExist", err)
	}
	tombstones, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".trustdb-key-envelope-delete-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tombstones) != 0 {
		t.Fatalf("successful RemoveFile left encrypted tombstones: %v", tombstones)
	}
}

func TestWindowsEnvelopeStorageRejectsBroadenedDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.material")
	provider := testPassphraseProvider("windows ACL passphrase")
	data, err := sealWithRand(
		context.Background(),
		testMetadata,
		bytes.Repeat([]byte{0x51}, 64),
		provider,
		deterministicReader(51),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, data); err != nil {
		t.Fatal(err)
	}
	world, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := currentProcessUserSID()
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(owner),
			},
		},
		{
			AccessPermissions: windows.GENERIC_READ,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(world),
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(path); !errors.Is(err, ErrUnsafeEnvelopeStorage) {
		t.Fatalf("ReadFile with broadened DACL error = %v, want unsafe storage", err)
	}
}

func TestWindowsEnvelopeLockHonorsContextAndRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.material")
	lockPath := path + ".lock"
	release, err := acquireEnvelopeLock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(lockPath, lockPath+".renamed"); err == nil {
		t.Fatal("held lock file was renamed")
	}
	if err := os.Remove(lockPath); err == nil {
		t.Fatal("held lock file was removed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := acquireEnvelopeLock(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second lock error = %v, want deadline exceeded", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	recovered, err := acquireEnvelopeLock(context.Background(), path)
	if err != nil {
		t.Fatalf("lock did not recover after release: %v", err)
	}
	if err := recovered(); err != nil {
		t.Fatal(err)
	}
}
