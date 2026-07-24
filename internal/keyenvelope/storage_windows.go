//go:build windows

package keyenvelope

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func storageSupported() bool { return true }

func secureEnvelopeFile(file *os.File, _ fs.FileMode) error {
	if err := setOwnerOnlyACL(windows.Handle(file.Fd())); err != nil {
		return secretSafePathError("protect software key envelope", err)
	}
	info, err := file.Stat()
	if err != nil {
		return secretSafePathError("stat software key envelope", err)
	}
	return validateEnvelopeFile(file, info)
}

func validateEnvelopeFile(file *os.File, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: envelope is not a regular file", ErrUnsafeEnvelopeStorage)
	}
	handle := windows.Handle(file.Fd())
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &handleInfo); err != nil {
		return secretSafePathError("inspect software key envelope handle", err)
	}
	if handleInfo.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return fmt.Errorf("%w: envelope is a reparse point or directory", ErrUnsafeEnvelopeStorage)
	}
	if err := validateOwnerOnlyACL(handle); err != nil {
		return fmt.Errorf("%w: envelope owner ACL is invalid", ErrUnsafeEnvelopeStorage)
	}
	return nil
}

func acquireEnvelopeLock(ctx context.Context, path string) (func() error, error) {
	lockPath := path + ".lock"
	name, err := windows.UTF16PtrFromString(lockPath)
	if err != nil {
		return nil, secretSafePathError("encode software key envelope lock", err)
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_HIDDEN|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, secretSafePathError("open software key envelope lock", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = windows.CloseHandle(handle)
		}
	}()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, secretSafePathError("inspect software key envelope lock", err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return nil, fmt.Errorf("%w: lock file is a reparse point or directory", ErrUnsafeEnvelopeStorage)
	}
	if err := setOwnerOnlyACL(handle); err != nil {
		return nil, secretSafePathError("protect software key envelope lock", err)
	}
	if err := validateOwnerOnlyACL(handle); err != nil {
		return nil, fmt.Errorf("%w: lock file owner ACL is invalid", ErrUnsafeEnvelopeStorage)
	}

	overlapped := new(windows.Overlapped)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		err = windows.LockFileEx(
			handle,
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0,
			^uint32(0),
			^uint32(0),
			overlapped,
		)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_IO_PENDING) {
			return nil, secretSafePathError("lock software key envelope", err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
	closeOnError = false
	return func() error {
		return errors.Join(
			windows.UnlockFileEx(handle, 0, ^uint32(0), ^uint32(0), overlapped),
			windows.CloseHandle(handle),
		)
	}, nil
}

func setOwnerOnlyACL(handle windows.Handle) error {
	owner, err := currentProcessUserSID()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(owner),
		},
	}}, nil)
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION|
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner,
		nil,
		acl,
		nil,
	)
}

func validateOwnerOnlyACL(handle windows.Handle) error {
	expectedOwner, err := currentProcessUserSID()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	if descriptor == nil {
		return errors.New("missing security descriptor")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(expectedOwner) {
		return errors.New("unexpected envelope owner")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("envelope DACL inherits permissions")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if dacl == nil || dacl.AceCount != 1 {
		return errors.New("envelope DACL must have one owner entry")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return err
	}
	if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
		return errors.New("envelope owner entry is invalid")
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !expectedOwner.Equals(aceSID) || ace.Mask&windows.GENERIC_ALL == 0 {
		return errors.New("envelope DACL grants an unexpected principal")
	}
	return nil
}

func currentProcessUserSID() (*windows.SID, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	if user == nil || user.User.Sid == nil {
		return nil, errors.New("current process has no user SID")
	}
	return user.User.Sid.Copy()
}

func atomicInstall(src, dst string) error {
	return moveFile(src, dst, windows.MOVEFILE_WRITE_THROUGH)
}

func atomicReplace(src, dst string) error {
	return moveFile(src, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func removeFileDurable(path string) error {
	var random [16]byte
	for attempts := 0; attempts < 8; attempts++ {
		if _, err := rand.Read(random[:]); err != nil {
			return err
		}
		tombstone := filepath.Join(
			filepath.Dir(path),
			".trustdb-key-envelope-delete-"+hex.EncodeToString(random[:])+".tmp",
		)
		err := moveFile(path, tombstone, windows.MOVEFILE_WRITE_THROUGH)
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
			continue
		}
		if err != nil {
			return err
		}
		// The write-through rename is the durability boundary: after it
		// succeeds, a crash can leave only an encrypted orphan tombstone and
		// can never restore private material at the canonical path.
		return os.Remove(tombstone)
	}
	return errors.New("could not allocate a software key envelope tombstone")
}

func moveFile(src, dst string, flags uint32) error {
	source, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(source, target, flags)
}

func syncDirectory(path string) error {
	// Windows does not document FlushFileBuffers for directory handles.
	// atomicInstall, atomicReplace, and the delete tombstone rename use
	// MOVEFILE_WRITE_THROUGH as their supported persistence boundary.
	return nil
}
