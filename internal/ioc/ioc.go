// Package ioc holds the indicators of compromise for the sample and the
// matching rules used to decide whether a process, registry entry or file
// belongs to it. It is platform independent so it can be unit tested anywhere.
package ioc

import (
	"path/filepath"
	"strings"

	"defuse/internal/config"
)

// IOC describes what the malware looks like on a system.
type IOC struct {
	KeyName    string   // Run registry value name
	InstallRel string   // install path relative to its root, e.g. maltrack\maltrack.exe
	Dir        string   // install directory name, e.g. maltrack
	Names      []string // executable file names (lower case)
	Mutex      string
}

// Default returns the indicators found by static analysis of the sample
// (decrypted DCDATA: KEYNAME, EDTPATH, MUTEX, SID).
func Default() IOC {
	return FromConfig(&config.Config{
		KeyName:     "Mal-Track",
		InstallPath: `maltrack\maltrack.exe`,
		Mutex:       "DCMIN_MUTEX-NLY9NFG",
		SID:         "mal-track",
	})
}

// FromConfig derives indicators from a decrypted DarkComet configuration.
func FromConfig(c *config.Config) IOC {
	i := IOC{
		KeyName:    c.KeyName,
		InstallRel: strings.ToLower(filepath.ToSlash(c.InstallPath)),
		Mutex:      c.Mutex,
	}
	i.InstallRel = strings.ReplaceAll(i.InstallRel, "/", `\`)

	if dir, file, ok := cutLast(i.InstallRel, `\`); ok {
		i.Dir = dir
		i.Names = append(i.Names, file)
	} else if i.InstallRel != "" {
		i.Names = append(i.Names, i.InstallRel)
	}
	// The dropper keeps the original file name (the SID is the builder name).
	if c.SID != "" {
		i.Names = append(i.Names, strings.ToLower(c.SID)+".exe")
	}
	return i
}

func cutLast(s, sep string) (before, after string, ok bool) {
	idx := strings.LastIndex(s, sep)
	if idx < 0 {
		return "", s, false
	}
	return s[:idx], s[idx+len(sep):], true
}

// MatchName reports whether a registry value name is the malware's Run name.
func (i IOC) MatchName(name string) bool {
	return i.KeyName != "" && strings.EqualFold(strings.TrimSpace(name), i.KeyName)
}

// MatchCommand reports whether a command line or path refers to the malware.
func (i IOC) MatchCommand(cmd string) bool {
	l := strings.ToLower(cmd)
	if i.InstallRel != "" && strings.Contains(l, i.InstallRel) {
		return true
	}
	for _, n := range i.Names {
		if strings.Contains(l, `\`+n) || l == n || strings.HasPrefix(l, `"`+n) {
			return true
		}
	}
	return false
}

// MatchImage reports whether an executable path looks like the malware.
func (i IOC) MatchImage(path string) bool {
	if path == "" {
		return false
	}
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(path, `\`, "/")))
	for _, n := range i.Names {
		if base == n {
			return true
		}
	}
	return i.MatchCommand(path)
}

// IsInstallPath reports whether path is exactly the malware's install location.
func (i IOC) IsInstallPath(path string) bool {
	return i.InstallRel != "" && strings.HasSuffix(strings.ToLower(path), `\`+i.InstallRel)
}

// ExePath extracts the executable path from a Run-value command line
// (quoted or unquoted, with optional arguments).
func ExePath(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if strings.HasPrefix(cmd, `"`) {
		if end := strings.Index(cmd[1:], `"`); end >= 0 {
			return cmd[1 : 1+end]
		}
		return strings.Trim(cmd, `"`)
	}
	lower := strings.ToLower(cmd)
	if idx := strings.Index(lower, ".exe"); idx >= 0 {
		return cmd[:idx+4]
	}
	return cmd
}
