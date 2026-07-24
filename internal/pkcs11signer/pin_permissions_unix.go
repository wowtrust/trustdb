//go:build !windows

package pkcs11signer

import "os"

func pinFilePermissionsSafe(info os.FileInfo) bool {
	return info.Mode().Perm()&0o077 == 0
}
