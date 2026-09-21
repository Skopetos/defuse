//go:build windows

// Package win wraps the Windows APIs the removal tool needs.
package win

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Process is one entry of the running process list.
type Process struct {
	PID  uint32
	PPID uint32
	Name string
	Path string // full image path; empty if it cannot be queried
}

// Processes returns a snapshot of all running processes.
func Processes() ([]Process, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("process snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := windows.Process32First(snap, &e); err != nil {
		return nil, fmt.Errorf("process list: %w", err)
	}

	var out []Process
	for {
		p := Process{
			PID:  e.ProcessID,
			PPID: e.ParentProcessID,
			Name: windows.UTF16ToString(e.ExeFile[:]),
		}
		p.Path = imagePath(p.PID)
		out = append(out, p)
		if err := windows.Process32Next(snap, &e); err != nil {
			break // ERROR_NO_MORE_FILES
		}
	}
	return out, nil
}

func imagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// Descendants returns every process that descends from any of the given PIDs
// (for example the cmd.exe a RAT spawns for its remote shell).
func Descendants(all []Process, roots []uint32) []Process {
	seen := map[uint32]bool{}
	for _, r := range roots {
		seen[r] = true
	}
	var out []Process
	for changed := true; changed; {
		changed = false
		for _, p := range all {
			if !seen[p.PID] && seen[p.PPID] && p.PID != p.PPID {
				seen[p.PID] = true
				out = append(out, p)
				changed = true
			}
		}
	}
	return out
}

// Kill terminates a process and waits for it to exit.
func Kill(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return fmt.Errorf("open pid %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)

	if err := windows.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("terminate pid %d: %w", pid, err)
	}
	if ev, err := windows.WaitForSingleObject(h, 5000); err != nil || ev != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("pid %d did not exit in time", pid)
	}
	return nil
}
