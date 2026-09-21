//go:build !windows

package main

import (
	"fmt"
	"os"
)

// runClean is Windows-only; other platforms can still use -analyze.
func runClean(bool) int {
	fmt.Fprintln(os.Stderr, "[!] Removal only works on Windows. Build with GOOS=windows, or use -analyze FILE here.")
	return 2
}
