//go:build windows

package win

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"

	"defuse/internal/ioc"
)

// Persistence is one autostart entry that belongs to the malware.
type Persistence struct {
	Kind     string // what sort of entry it is
	Location string // where it lives, human readable
	Detail   string // the command / target it launches
	remove   func() error
}

// Remove deletes (or restores) the entry.
func (p Persistence) Remove() error { return p.remove() }

type regLoc struct {
	root     registry.Key
	rootName string
	path     string
}

// The four keys checked by the audit, plus the 32-bit view and policy keys.
var runLocations = []regLoc{
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\Run`},
	{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`},
	{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`},
}

// DarkComet also writes to Winlogon (Userinit/Shell) and keeps msconfig
// bookkeeping keys, so those are inspected too.
var winlogonLocations = []regLoc{
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`},
	{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`},
}

var msconfigLocations = []regLoc{
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Shared Tools\MSConfig\startupreg`},
	{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Shared Tools\MSConfig\startupfolder`},
}

// FindPersistence returns every autostart entry that matches the indicators.
// Locations that cannot be opened (missing key, no rights) are skipped; the
// returned warnings say which ones so the caller can report them.
func FindPersistence(i ioc.IOC) (found []Persistence, warnings []string) {
	for _, loc := range runLocations {
		f, w := scanRunKey(i, loc)
		found, warnings = append(found, f...), append(warnings, w...)
	}
	for _, loc := range winlogonLocations {
		f, w := scanWinlogon(i, loc)
		found, warnings = append(found, f...), append(warnings, w...)
	}
	for _, loc := range msconfigLocations {
		f, w := scanMSConfig(i, loc)
		found, warnings = append(found, f...), append(warnings, w...)
	}
	found = append(found, scanStartupFolders(i)...)
	return found, warnings
}

func (l regLoc) String() string { return l.rootName + `\` + l.path }

func scanRunKey(i ioc.IOC, loc regLoc) (found []Persistence, warnings []string) {
	k, err := registry.OpenKey(loc.root, loc.path, registry.QUERY_VALUE)
	if err != nil {
		if err != registry.ErrNotExist {
			warnings = append(warnings, fmt.Sprintf("cannot read %s: %v", loc, err))
		}
		return nil, warnings
	}
	names, err := k.ReadValueNames(-1)
	k.Close()
	if err != nil {
		return nil, append(warnings, fmt.Sprintf("cannot list %s: %v", loc, err))
	}

	for _, name := range names {
		data := readString(loc, name)
		if !i.MatchName(name) && !i.MatchCommand(data) {
			continue
		}
		name, loc := name, loc
		found = append(found, Persistence{
			Kind:     "registry Run value",
			Location: fmt.Sprintf(`%s\%s`, loc, name),
			Detail:   data,
			remove: func() error {
				k, err := registry.OpenKey(loc.root, loc.path, registry.SET_VALUE)
				if err != nil {
					return err
				}
				defer k.Close()
				return k.DeleteValue(name)
			},
		})
	}
	return found, warnings
}

func readString(loc regLoc, name string) string {
	k, err := registry.OpenKey(loc.root, loc.path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	s, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return s
}

// scanWinlogon looks for the malware chained onto Userinit or Shell. In HKLM
// the value is restored to its Windows default; in HKCU it is removed.
func scanWinlogon(i ioc.IOC, loc regLoc) (found []Persistence, warnings []string) {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	defaults := map[string]string{
		"Userinit": filepath.Join(sysRoot, "system32", "userinit.exe") + ",",
		"Shell":    "explorer.exe",
	}

	for name, def := range defaults {
		data := readString(loc, name)
		if data == "" || !i.MatchCommand(data) {
			continue
		}
		name, def, loc := name, def, loc
		found = append(found, Persistence{
			Kind:     "Winlogon hook",
			Location: fmt.Sprintf(`%s\%s`, loc, name),
			Detail:   data,
			remove: func() error {
				k, err := registry.OpenKey(loc.root, loc.path, registry.SET_VALUE)
				if err != nil {
					return err
				}
				defer k.Close()
				if loc.root == registry.CURRENT_USER {
					return k.DeleteValue(name)
				}
				return k.SetStringValue(name, def)
			},
		})
	}
	return found, nil
}

// scanMSConfig finds msconfig's own bookkeeping subkeys (used by the
// "Startup" tab) that name the malware.
func scanMSConfig(i ioc.IOC, loc regLoc) (found []Persistence, warnings []string) {
	k, err := registry.OpenKey(loc.root, loc.path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		if err != registry.ErrNotExist {
			warnings = append(warnings, fmt.Sprintf("cannot read %s: %v", loc, err))
		}
		return nil, warnings
	}
	subs, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil {
		return nil, warnings
	}

	for _, sub := range subs {
		sk, err := registry.OpenKey(loc.root, loc.path+`\`+sub, registry.QUERY_VALUE)
		command := ""
		if err == nil {
			command, _, _ = sk.GetStringValue("command")
			sk.Close()
		}
		if !i.MatchName(sub) && !i.MatchCommand(command) && !i.MatchCommand(sub) {
			continue
		}
		sub, loc := sub, loc
		found = append(found, Persistence{
			Kind:     "msconfig startup entry",
			Location: fmt.Sprintf(`%s\%s`, loc, sub),
			Detail:   command,
			remove: func() error {
				return registry.DeleteKey(loc.root, loc.path+`\`+sub)
			},
		})
	}
	return found, warnings
}

// StartupFolders returns the per-user and all-users Startup directories.
func StartupFolders() []string {
	var dirs []string
	if v := os.Getenv("APPDATA"); v != "" {
		dirs = append(dirs, filepath.Join(v, `Microsoft\Windows\Start Menu\Programs\Startup`))
	}
	if v := os.Getenv("ProgramData"); v != "" {
		dirs = append(dirs, filepath.Join(v, `Microsoft\Windows\Start Menu\Programs\StartUp`))
	}
	return dirs
}

// scanStartupFolders finds files in the Startup folders that are, or launch,
// the malware: matched by name, or by the target stored inside a shortcut/script.
func scanStartupFolders(i ioc.IOC) []Persistence {
	var found []Persistence
	for _, dir := range StartupFolders() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(dir, e.Name())
			if !i.MatchImage(path) && !fileMentions(path, i) {
				continue
			}
			found = append(found, Persistence{
				Kind:     "Startup folder item",
				Location: path,
				remove:   func() error { return RemoveFile(path) },
			})
		}
	}
	return found
}

// fileMentions reports whether a small shortcut/script file references the
// malware (checked as ASCII and UTF-16, since .lnk files store both).
func fileMentions(path string, i ioc.IOC) bool {
	info, err := os.Stat(path)
	if err != nil || info.Size() > 1<<20 {
		return false
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".lnk", ".url", ".bat", ".cmd", ".vbs", ".js", ".ps1":
	default:
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	lower := bytes.ToLower(data)
	for _, needle := range append([]string{i.InstallRel}, i.Names...) {
		if needle == "" {
			continue
		}
		if bytes.Contains(lower, []byte(needle)) {
			return true
		}
		u := utf16.Encode([]rune(needle))
		wide := make([]byte, 0, len(u)*2)
		for _, c := range u {
			wide = append(wide, byte(c), byte(c>>8))
		}
		if bytes.Contains(lower, wide) {
			return true
		}
	}
	return false
}
