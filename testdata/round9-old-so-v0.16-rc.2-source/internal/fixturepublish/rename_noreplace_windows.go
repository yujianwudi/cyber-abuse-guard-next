//go:build windows

package fixturepublish

import "golang.org/x/sys/windows"

func renameNoReplace(oldPath, newPath string) error {
	oldName, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newName, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	// Deliberately omit MOVEFILE_REPLACE_EXISTING. The source and destination
	// share a parent directory, so this remains a same-volume native rename;
	// WRITE_THROUGH waits for the directory entry update to reach storage.
	return windows.MoveFileEx(oldName, newName, windows.MOVEFILE_WRITE_THROUGH)
}
