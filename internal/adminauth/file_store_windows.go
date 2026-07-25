//go:build windows

package adminauth

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func securePolicyFile(file *os.File) error {
	owner, err := currentPolicyUserSID()
	if err != nil {
		return err
	}
	acl, err := policyOwnerACL(owner)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(
		file.Name(), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, acl, nil,
	); err != nil {
		return fmt.Errorf("protect admin policy file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	return validatePolicyFilePermissions(file.Name(), info)
}

func validatePolicyFilePermissions(path string, _ os.FileInfo) error {
	descriptor, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("%w: inspect policy ACL: %v", ErrUnsafeStorage, err)
	}
	expectedOwner, err := currentPolicyUserSID()
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(expectedOwner) {
		return fmt.Errorf("%w: policy owner is not the current user", ErrUnsafeStorage)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%w: policy DACL inherits permissions", ErrUnsafeStorage)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if dacl == nil || dacl.AceCount != 1 {
		return fmt.Errorf("%w: policy DACL must contain one owner entry", ErrUnsafeStorage)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return err
	}
	if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
		return fmt.Errorf("%w: policy owner ACE is invalid", ErrUnsafeStorage)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !expectedOwner.Equals(aceSID) || !policyFullFileAccess(ace.Mask) {
		return fmt.Errorf("%w: policy DACL grants an unexpected principal or access mask", ErrUnsafeStorage)
	}
	return nil
}

func currentPolicyUserSID() (*windows.SID, error) {
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

func policyOwnerACL(owner *windows.SID) (*windows.ACL, error) {
	return windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(owner),
		},
	}}, nil)
}

func policyFullFileAccess(mask windows.ACCESS_MASK) bool {
	const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff
	return mask&windows.GENERIC_ALL != 0 || mask&fileAllAccess == fileAllAccess
}

func installPolicyFile(source, target string, replace bool) error {
	if !replace {
		if _, err := os.Lstat(target); err == nil {
			return fs.ErrExist
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	sourcePath, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	targetPath, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return windows.MoveFileEx(sourcePath, targetPath, flags)
}

func syncPolicyDirectory(string) error { return nil }
