//go:build windows

package win

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"defuse/internal/ioc"
)

// InstallCandidates returns every place DarkComet may have copied itself to.
// The install root is a builder option (COMBOPATH) that is not decoded here,
// so all the usual roots are combined with the configured relative path.
func InstallCandidates(i ioc.IOC) []string {
	if i.InstallRel == "" {
		return nil
	}
	roots := []string{
		os.Getenv("APPDATA"),
		os.Getenv("LOCALAPPDATA"),
		os.Getenv("USERPROFILE"),
		os.Getenv("TEMP"),
		os.Getenv("SystemRoot"),
		os.Getenv("ProgramFiles"),
		os.Getenv("ProgramFiles(x86)"),
		os.Getenv("ProgramData"),
	}
	if v := os.Getenv("USERPROFILE"); v != "" {
		roots = append(roots, filepath.Join(v, "Documents"))
	}
	if v := os.Getenv("SystemRoot"); v != "" {
		roots = append(roots, filepath.Join(v, "System32"), filepath.Join(v, "SysWOW64"))
	}

	seen := map[string]bool{}
	var out []string
	for _, r := range roots {
		if r == "" {
			continue
		}
		p := filepath.Join(r, i.InstallRel)
		if key := strings.ToLower(p); !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	return out
}

// Exists reports whether path exists (hidden/system files included).
func Exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// RemoveFile deletes a file even if DarkComet marked it read-only/hidden/
// system. If it is still locked it is scheduled for deletion at next reboot.
func RemoveFile(path string) error {
	clearAttributes(path)
	err := os.Remove(path)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	from, perr := windows.UTF16PtrFromString(path)
	if perr != nil {
		return err
	}
	if merr := windows.MoveFileEx(from, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); merr != nil {
		return fmt.Errorf("%w (reboot-delete also failed: %v)", err, merr)
	}
	return fmt.Errorf("%w (scheduled for deletion at next reboot)", err)
}

// RemoveInstallDir removes the malware's install directory, including the
// dclogs keylogger folder. It refuses to touch any directory whose name is not
// exactly the configured one, so a wrong path can never wipe something else.
func RemoveInstallDir(dir, expectedName string) error {
	if expectedName == "" || !strings.EqualFold(filepath.Base(dir), expectedName) {
		return fmt.Errorf("refusing to remove %q: not the %q install directory", dir, expectedName)
	}
	filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err == nil {
			clearAttributes(p)
		}
		return nil
	})
	return os.RemoveAll(dir)
}

func clearAttributes(path string) {
	if p, err := windows.UTF16PtrFromString(path); err == nil {
		windows.SetFileAttributes(p, windows.FILE_ATTRIBUTE_NORMAL)
	}
}
