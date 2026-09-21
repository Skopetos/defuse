// defuse detects, neutralizes and removes the DarkComet "Fynloski" sample
// (mal-track.exe) from a Windows machine and reports the attacker's address.
//
// Usage:
//
//	defuse.exe              kill, clean, delete, verify, print attacker IP
//	defuse.exe -dry-run     show what would be done without changing anything
//	defuse.exe -analyze F   statically decrypt the config of file F (any OS)
package main

import (
	"flag"
	"fmt"
	"os"

	"defuse/internal/config"
)

func main() {
	dryRun := flag.Bool("dry-run", false, "show what would be removed without changing anything")
	analyze := flag.String("analyze", "", "statically extract the DarkComet config from `file` and exit (nothing is executed)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-dry-run] | [-analyze file]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *analyze != "" {
		os.Exit(runAnalyze(*analyze))
	}
	os.Exit(runClean(*dryRun))
}

// runAnalyze prints the decrypted configuration of a sample without running it.
func runAnalyze(path string) int {
	cfg, err := config.Extract(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s: %v\n", path, err)
		return 1
	}
	fmt.Printf("DarkComet configuration of %s\n", path)
	fmt.Printf("  Attacker (C2)   : %s  (host %s, port %s)\n", cfg.NetData, cfg.Host(), cfg.Port())
	fmt.Printf("  Run value name  : %s\n", cfg.KeyName)
	fmt.Printf("  Install path    : %s\n", cfg.InstallPath)
	fmt.Printf("  Mutex           : %s\n", cfg.Mutex)
	fmt.Printf("  Builder SID     : %s\n", cfg.SID)
	fmt.Printf("  Offline keylog  : %s\n", cfg.OfflineKey)
	return 0
}
