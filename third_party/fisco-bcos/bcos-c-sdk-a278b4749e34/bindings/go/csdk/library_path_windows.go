//go:build cgo && windows

package csdk

/*
#include <windows.h>
#include <stddef.h>
#include "../../../bcos-c-sdk/bcos_sdk_c.h"

typedef const char* (*trustdb_version_fn)(void);
extern trustdb_version_fn __imp_bcos_sdk_version;

static int trustdb_loaded_library_path(wchar_t* output, size_t capacity)
{
    if (output == NULL || capacity < 2) { return -1; }
    FARPROC target = (FARPROC)__imp_bcos_sdk_version;
    if (target == NULL) { return -1; }
    HMODULE module = NULL;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            (LPCWSTR)target,
            &module)) {
        return -1;
    }
    if (GetProcAddress(module, "bcos_sdk_version") != target) {
        FreeLibrary(module);
        return -3;
    }
    DWORD length = GetModuleFileNameW(module, output, (DWORD)capacity);
    FreeLibrary(module);
    if (length == 0 || length >= capacity) { return -2; }
    return (int)length;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"
)

var getLongPathNameW = syscall.NewLazyDLL("kernel32.dll").NewProc("GetLongPathNameW")

// LoadedLibraryPath returns the DLL that actually supplies bcos_sdk_version.
// Windows function addresses point at executable thunks, so the provider module
// is resolved from the actual IAT target and checked against its exported symbol.
func LoadedLibraryPath() (string, error) {
	buffer := make([]uint16, 32768)
	length := int(C.trustdb_loaded_library_path(
		(*C.wchar_t)(unsafe.Pointer(&buffer[0])),
		C.size_t(len(buffer)),
	))
	if length <= 0 || length >= len(buffer) {
		return "", errors.New("cannot resolve loaded FISCO BCOS native SDK path")
	}
	path, err := filepath.Abs(syscall.UTF16ToString(buffer[:length]))
	if err != nil {
		return "", err
	}
	path, err = longWindowsPath(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(path), nil
}

func longWindowsPath(path string) (string, error) {
	source, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, 32768)
	length, _, callErr := getLongPathNameW.Call(
		uintptr(unsafe.Pointer(source)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)
	if length == 0 {
		return "", fmt.Errorf("cannot expand loaded FISCO BCOS native SDK path: %w", callErr)
	}
	if length >= uintptr(len(buffer)) {
		return "", errors.New("loaded FISCO BCOS native SDK path is too long")
	}
	return syscall.UTF16ToString(buffer[:length]), nil
}
