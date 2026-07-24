//go:build cgo && !linux && !darwin && !windows

package csdk

import "errors"

func LoadedLibraryPath() (string, error) {
	return "", errors.New("loaded FISCO BCOS native SDK path is unsupported on this platform")
}
