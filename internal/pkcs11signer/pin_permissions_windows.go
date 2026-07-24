//go:build windows

package pkcs11signer

import "os"

// Windows PIN files fail closed until owner-only DACL validation is
// continuously runtime-qualified across supported Windows editions and
// filesystems. The non-native stub and portable contract remain buildable.
func pinFilePermissionsSafe(os.FileInfo) bool {
	return false
}
