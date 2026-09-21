package ioc

import "testing"

func TestMatchName(t *testing.T) {
	i := Default()
	for name, want := range map[string]bool{
		"Mal-Track":  true,
		"mal-track":  true,
		" Mal-Track": true,
		"OneDrive":   false,
		"":           false,
	} {
		if got := i.MatchName(name); got != want {
			t.Errorf("MatchName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestMatchCommand(t *testing.T) {
	i := Default()
	for cmd, want := range map[string]bool{
		`C:\Users\a\Documents\maltrack\maltrack.exe`:            true,
		`"C:\Users\a\AppData\Roaming\MalTrack\maltrack.exe" -x`: true,
		`C:\Users\a\Downloads\mal-track.exe`:                    true,
		`C:\Windows\explorer.exe`:                               false,
		`"C:\Program Files\Tracker\tracker.exe"`:                false,
	} {
		if got := i.MatchCommand(cmd); got != want {
			t.Errorf("MatchCommand(%q) = %v, want %v", cmd, got, want)
		}
	}
}

func TestMatchImageAndInstallPath(t *testing.T) {
	i := Default()
	if !i.MatchImage(`C:\x\MalTrack.EXE`) {
		t.Error("MatchImage should be case-insensitive")
	}
	if i.MatchImage(`C:\x\notepad.exe`) || i.MatchImage("") {
		t.Error("MatchImage matched something it should not")
	}
	if !i.IsInstallPath(`C:\Users\a\Documents\maltrack\maltrack.exe`) {
		t.Error("IsInstallPath should match the install location")
	}
	if i.IsInstallPath(`C:\Users\a\Downloads\mal-track.exe`) {
		t.Error("IsInstallPath must not match the original dropper")
	}
}

func TestExePath(t *testing.T) {
	for cmd, want := range map[string]string{
		`"C:\a b\x.exe" /s`: `C:\a b\x.exe`,
		`C:\a\x.exe /s`:     `C:\a\x.exe`,
		`C:\a\x.exe`:        `C:\a\x.exe`,
	} {
		if got := ExePath(cmd); got != want {
			t.Errorf("ExePath(%q) = %q, want %q", cmd, got, want)
		}
	}
}
