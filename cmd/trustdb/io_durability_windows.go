//go:build windows

package main

import "golang.org/x/sys/windows"

func replaceFileDurable(source, target string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(
		from,
		to,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}

func syncDirectoryDurable(string) error {
	// MOVEFILE_WRITE_THROUGH is the supported Windows persistence boundary.
	return nil
}
