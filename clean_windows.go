//go:build windows

package main

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"defuse/internal/config"
	"defuse/internal/ioc"
	"defuse/internal/win"
)

func say(tag, format string, args ...any) {
	fmt.Printf("  [%s] %s\n", tag, fmt.Sprintf(format, args...))
}
func step(n int, title string) { fmt.Printf("\n== %d. %s ==\n", n, title) }

// runClean runs the whole detect / kill / clean / verify sequence.
// It returns 0 only if the verification pass finds nothing left.
func runClean(dryRun bool) int {
	i := ioc.Default()
	mode := "REMOVAL"
	if dryRun {
		mode = "DRY RUN - nothing will be changed"
	}
	fmt.Printf("defuse: DarkComet/Fynloski (mal-track.exe) removal tool [%s]\n", mode)
	if !windows.GetCurrentProcessToken().IsElevated() {
		say("!", "not running as Administrator: HKLM entries and system paths may not be removable")
	}

	// ---- 1. locate --------------------------------------------------------
	step(1, "Locating the malware")
	procs, err := win.Processes()
	if err != nil {
		say("!", "%v", err)
		return 1
	}
	persist, warnings := win.FindPersistence(i)
	for _, w := range warnings {
		say("!", "%s", w)
	}

	verified := map[string]*config.Config{} // lower-case path -> decrypted config
	var files []string                      // paths of malware binaries, in discovery order
	addFile := func(path string) {
		key := strings.ToLower(path)
		if path == "" || !win.Exists(path) {
			return
		}
		if _, done := verified[key]; done {
			return
		}
		cfg, err := config.Extract(path)
		if err != nil {
			verified[key] = nil
			say("!", "%s matches by name but has no DarkComet config (%v): left alone", path, err)
			return
		}
		verified[key] = cfg
		files = append(files, path)
		say("+", "confirmed DarkComet binary: %s", path)
	}

	var targets []win.Process
	for _, p := range procs {
		if !i.MatchImage(p.Path) {
			continue
		}
		addFile(p.Path)
		if verified[strings.ToLower(p.Path)] != nil || i.IsInstallPath(p.Path) {
			targets = append(targets, p)
			say("+", "malware process: %s (PID %d)", p.Path, p.PID)
		}
	}
	for _, p := range persist {
		addFile(ioc.ExePath(p.Detail))
	}
	for _, c := range win.InstallCandidates(i) {
		addFile(c)
	}
	if len(targets) == 0 && len(files) == 0 && len(persist) == 0 {
		say("+", "no trace of the malware found")
	}
	for _, p := range persist {
		say("+", "persistence: %s -> %s  [%s]", p.Location, p.Detail, p.Kind)
	}

	// ---- 2. attacker ------------------------------------------------------
	step(2, "Attacker information")
	cfg := firstConfig(files, verified)
	report := attackerReport(cfg, targets)
	for _, line := range report.lines {
		say("i", "%s", line)
	}

	if dryRun {
		step(3, "Actions that would be taken")
		for _, p := range targets {
			say("-", "kill PID %d (%s) and its child processes", p.PID, p.Name)
		}
		for _, p := range persist {
			say("-", "remove %s", p.Location)
		}
		for _, f := range files {
			say("-", "delete %s", f)
		}
		printAttacker(report)
		return 0
	}

	// ---- 3. kill ----------------------------------------------------------
	step(3, "Terminating malware processes")
	for round := 1; round <= 3; round++ {
		all, err := win.Processes()
		if err != nil {
			say("!", "%v", err)
			break
		}
		roots := matchingPIDs(all, i, verified)
		if len(roots) == 0 {
			if round == 1 {
				say("i", "no malware process running")
			}
			break
		}
		// Children first (e.g. the cmd.exe of the remote shell), then the RAT.
		for _, c := range win.Descendants(all, roots) {
			kill(c.PID, c.Name)
		}
		for _, p := range all {
			for _, r := range roots {
				if p.PID == r {
					kill(p.PID, p.Name)
				}
			}
		}
		time.Sleep(500 * time.Millisecond) // give a watchdog time to respawn, then re-check
	}

	// ---- 4. persistence ---------------------------------------------------
	step(4, "Removing persistence")
	if len(persist) == 0 {
		say("i", "no persistence entries found")
	}
	for _, p := range persist {
		if err := p.Remove(); err != nil {
			say("!", "could not remove %s: %v", p.Location, err)
			continue
		}
		say("+", "removed %s", p.Location)
	}

	// ---- 5. files ---------------------------------------------------------
	step(5, "Deleting malware files")
	if len(files) == 0 {
		say("i", "no malware files found")
	}
	dirs := map[string]bool{}
	for _, f := range files {
		if err := win.RemoveFile(f); err != nil {
			say("!", "%s: %v", f, err)
		} else {
			say("+", "deleted %s", f)
		}
		if dir := filepath.Dir(f); i.Dir != "" && strings.EqualFold(filepath.Base(dir), i.Dir) {
			dirs[dir] = true
		}
	}
	for dir := range dirs {
		if err := win.RemoveInstallDir(dir, i.Dir); err != nil {
			say("!", "%s: %v", dir, err)
		} else {
			say("+", "deleted install directory %s (incl. dclogs keylogger data)", dir)
		}
	}

	// ---- 6. verify --------------------------------------------------------
	step(6, "Verification")
	clean := verify(i, verified)
	printAttacker(report)
	if !clean {
		fmt.Println("\nResult: NOT clean - see [FAIL] lines above (a reboot may be needed for locked files).")
		return 1
	}
	fmt.Println("\nResult: system is clean.")
	return 0
}

func kill(pid uint32, name string) {
	if err := win.Kill(pid); err != nil {
		say("!", "%v", err)
		return
	}
	say("+", "terminated %s (PID %d)", name, pid)
}

// matchingPIDs returns the PIDs of running malware processes.
func matchingPIDs(all []win.Process, i ioc.IOC, verified map[string]*config.Config) []uint32 {
	var pids []uint32
	for _, p := range all {
		if !i.MatchImage(p.Path) {
			continue
		}
		if verified[strings.ToLower(p.Path)] != nil || i.IsInstallPath(p.Path) {
			pids = append(pids, p.PID)
		}
	}
	return pids
}

// verify re-checks processes, persistence and files, printing PASS/FAIL.
func verify(i ioc.IOC, verified map[string]*config.Config) bool {
	ok := true
	result := func(good bool, what string) {
		tag := "PASS"
		if !good {
			tag, ok = "FAIL", false
		}
		say(tag, "%s", what)
	}

	all, err := win.Processes()
	if err != nil {
		say("!", "%v", err)
		return false
	}
	result(len(matchingPIDs(all, i, verified)) == 0, "no malware process running")

	left, _ := win.FindPersistence(i)
	result(len(left) == 0, "no persistence in Run/RunOnce, Winlogon, msconfig or Startup folders")
	for _, p := range left {
		say("i", "still present: %s", p.Location)
	}

	remaining := 0
	for _, c := range win.InstallCandidates(i) {
		if win.Exists(c) {
			remaining++
			say("i", "still present: %s", c)
		}
	}
	for path, cfg := range verified {
		if cfg != nil && win.Exists(path) {
			remaining++
			say("i", "still present: %s", path)
		}
	}
	result(remaining == 0, "malware files deleted")
	return ok
}

func firstConfig(files []string, verified map[string]*config.Config) *config.Config {
	for _, f := range files {
		if c := verified[strings.ToLower(f)]; c != nil {
			return c
		}
	}
	return nil
}

type attacker struct {
	lines []string
	ips   []string // final list for the summary
}

// attackerReport combines the C2 address from the decrypted config with the
// live connections of the running malware (like `netstat -ano`).
func attackerReport(cfg *config.Config, targets []win.Process) attacker {
	var a attacker
	seen := map[string]bool{}
	add := func(ip string) {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			a.ips = append(a.ips, ip)
		}
	}

	if cfg != nil {
		a.lines = append(a.lines, fmt.Sprintf("configured C2 (decrypted DCDATA): %s", cfg.NetData))
		host := cfg.Host()
		if ip := net.ParseIP(host); ip != nil {
			add(ip.String())
		} else if ips, err := net.LookupIP(host); err == nil {
			for _, ip := range ips {
				add(ip.String())
			}
			a.lines = append(a.lines, fmt.Sprintf("%s resolves to %v", host, ips))
		} else {
			a.lines = append(a.lines, fmt.Sprintf("%s could not be resolved: %v", host, err))
		}
	}

	pids := map[uint32]bool{}
	for _, p := range targets {
		pids[p.PID] = true
	}
	if conns, err := win.TCPConns(); err == nil {
		var live []string
		for _, c := range conns {
			if pids[c.PID] && !c.RemoteIP.IsUnspecified() {
				live = append(live, fmt.Sprintf("PID %d: %s:%d -> %s:%d (%s)",
					c.PID, c.LocalIP, c.LocalPort, c.RemoteIP, c.RemotePort, win.StateName(c.State)))
				add(c.RemoteIP.String())
			}
		}
		sort.Strings(live)
		for _, l := range live {
			a.lines = append(a.lines, "live connection "+l)
		}
		if len(pids) > 0 && len(live) == 0 {
			a.lines = append(a.lines, "no live connection right now (the RAT keeps retrying its C2)")
		}
	}
	if len(a.lines) == 0 {
		a.lines = append(a.lines, "no configuration or connection found")
	}
	return a
}

func printAttacker(a attacker) {
	fmt.Println()
	if len(a.ips) == 0 {
		fmt.Println("ATTACKER IP: not found")
		return
	}
	fmt.Printf("ATTACKER IP: %s\n", strings.Join(a.ips, ", "))
}
