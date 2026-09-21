package config

import (
	"os"
	"testing"
)

const samplePath = "../../sample/mal-track.exe.bin"

func TestExtractSample(t *testing.T) {
	if _, err := os.Stat(samplePath); err != nil {
		t.Skip("sample not present")
	}
	c, err := Extract(samplePath)
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string][2]string{
		"NetData":     {c.NetData, "127.0.0.1:1010"},
		"Host":        {c.Host(), "127.0.0.1"},
		"Port":        {c.Port(), "1010"},
		"KeyName":     {c.KeyName, "Mal-Track"},
		"InstallPath": {c.InstallPath, `maltrack\maltrack.exe`},
		"Mutex":       {c.Mutex, "DCMIN_MUTEX-NLY9NFG"},
		"SID":         {c.SID, "mal-track"},
	}
	for name, v := range checks {
		if v[0] != v[1] {
			t.Errorf("%s = %q, want %q", name, v[0], v[1])
		}
	}
}

func TestExtractRejectsNonPE(t *testing.T) {
	if _, err := ExtractBytes([]byte("hello")); err == nil {
		t.Fatal("expected error for non-PE input")
	}
}

func TestParse(t *testing.T) {
	c := parse("#BEGIN DARKCOMET DATA --\r\nNETDATA={10.0.0.5:1604}\r\nKEYNAME={X}\r\n#EOF DARKCOMET DATA --")
	if c.Host() != "10.0.0.5" || c.Port() != "1604" || c.KeyName != "X" {
		t.Fatalf("unexpected parse result: %+v", c)
	}
}
