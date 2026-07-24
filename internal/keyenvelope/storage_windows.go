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
	if err := setOwnerOnlyACL(file.Name(), windows.Handle(file.Fd()), true); err != nil {
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
		return fmt.Errorf("%w: envelope owner ACL is invalid: %v", ErrUnsafeEnvelopeStorage, err)
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
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_HIDDEN|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	created := err == nil
	if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		handle, err = windows.CreateFile(
			name,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_ATTRIBUTE_HIDDEN|windows.FILE_FLAG_OPEN_REPARSE_POINT,
			0,
		)
	}
	if err != nil {
		return nil, secretSafePathError("open software key envelope lock", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = windows.CloseHandle(handle)
			if created {
				_ = os.Remove(lockPath)
			}
		}
	}()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, secretSafePathError("inspect software key envelope lock", err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return nil, fmt.Errorf("%w: lock file is a reparse point or directory", ErrUnsafeEnvelopeStorage)
	}
	if err := setOwnerOnlyACL(lockPath, handle, created); err != nil {
		return nil, secretSafePathError("protect software key envelope lock", err)
	}
	if err := validateOwnerOnlyACL(handle); err != nil {
		return nil, fmt.Errorf("%w: lock file owner ACL is invalid: %v", ErrUnsafeEnvelopeStorage, err)
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

func setOwnerOnlyACL(path string, handle windows.Handle, maySetOwner bool) error {
	owner, err := currentProcessUserSID()
	if err != nil {
		return err
	}
	// Data handles do not carry WRITE_DAC. Reopen the same file without
	// share-delete and prove the file identity is unchanged. Newly created
	// objects may inherit the token's default owner (for example,
	// BUILTIN\Administrators) instead of TokenUser, so creation paths may
	// replace that owner with the current user. Existing lock files must
	// already have the expected owner and are never taken over.
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	securityHandle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(securityHandle)
	if err := requireSameFileHandle(handle, securityHandle); err != nil {
		return err
	}
	descriptor, err := windows.GetSecurityInfo(
		securityHandle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	actualOwner, _, err := descriptor.Owner()
	if err != nil || actualOwner == nil {
		return errors.New("software key envelope owner is unavailable")
	}
	ownerMatches := actualOwner.Equals(owner)
	if !ownerMatches && !maySetOwner {
		return errors.New("software key envelope owner is not the current user")
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
	if err := windows.SetSecurityInfo(
		securityHandle,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return err
	}
	if ownerMatches {
		return nil
	}

	// The new protected DACL gives TokenUser the right to reopen the file with
	// WRITE_OWNER even when the token's default owner was an administrator
	// group. Keep the first security handle open so the pathname cannot be
	// replaced between the DACL and ownership updates.
	ownerHandle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL|windows.WRITE_OWNER,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ownerHandle)
	if err := requireSameFileHandle(handle, ownerHandle); err != nil {
		return err
	}
	return windows.SetSecurityInfo(
		ownerHandle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		owner,
		nil,
		nil,
		nil,
	)
}

func requireSameFileHandle(left, right windows.Handle) error {
	var leftInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(left, &leftInfo); err != nil {
		return err
	}
	var rightInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(right, &rightInfo); err != nil {
		return err
	}
	if leftInfo.VolumeSerialNumber != rightInfo.VolumeSerialNumber ||
		leftInfo.FileIndexHigh != rightInfo.FileIndexHigh ||
		leftInfo.FileIndexLow != rightInfo.FileIndexLow {
		return errors.New("software key envelope path changed during ACL installation")
	}
	if rightInfo.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return errors.New("software key envelope security handle is unsafe")
	}
	return nil
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
	if !expectedOwner.Equals(aceSID) {
		return errors.New("envelope DACL grants an unexpected principal")
	}
	if !grantsFullFileAccess(ace.Mask) {
		return errors.New("envelope owner entry does not grant full file access")
	}
	return nil
}

func grantsFullFileAccess(mask windows.ACCESS_MASK) bool {
	// SetSecurityInfo maps GENERIC_ALL to the concrete file access mask. Some
	// filesystems preserve the generic bit, while NTFS normally stores
	// FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1ff).
	const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff
	return mask&windows.GENERIC_ALL != 0 ||
		mask&fileAllAccess == fileAllAccess
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
