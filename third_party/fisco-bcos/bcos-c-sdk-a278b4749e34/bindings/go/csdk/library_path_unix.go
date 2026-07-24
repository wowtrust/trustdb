//go:build cgo && (linux || darwin)

package csdk

/*
#define _GNU_SOURCE
#cgo linux LDFLAGS: -ldl
#include <dlfcn.h>
#include <stddef.h>
#include "../../../bcos-c-sdk/bcos_sdk_c.h"

static int trustdb_loaded_library_path(char* output, size_t capacity)
{
    if (output == NULL || capacity < 2) { return -1; }
    Dl_info info;
    if (dladdr((void*)&bcos_sdk_version, &info) == 0 || info.dli_fname == NULL) {
        return -1;
    }
    size_t length = 0;
    while (info.dli_fname[length] != '\0') {
        if (length + 1 >= capacity) { return -2; }
        output[length] = info.dli_fname[length];
        ++length;
    }
    output[length] = '\0';
    return (int)length;
}
*/
import "C"

import (
	"errors"
	"path/filepath"
	"unsafe"
)

// LoadedLibraryPath returns the image that actually supplies
// bcos_sdk_version, rather than an environment/configuration guess.
func LoadedLibraryPath() (string, error) {
	buffer := make([]byte, 4096)
	length := int(C.trustdb_loaded_library_path(
		(*C.char)(unsafe.Pointer(&buffer[0])),
		C.size_t(len(buffer)),
	))
	if length <= 0 || length >= len(buffer) {
		return "", errors.New("cannot resolve loaded FISCO BCOS native SDK path")
	}
	path, err := filepath.Abs(string(buffer[:length]))
	if err != nil {
		return "", err
	}
	return filepath.Clean(path), nil
}
