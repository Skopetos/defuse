// Package config statically extracts the embedded DarkComet ("Fynloski")
// configuration from a sample. Nothing is executed: the PE is parsed, the
// DCDATA resource is located, hex-decoded and RC4-decrypted.
package config

import (
	"bytes"
	"crypto/rc4"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf16"
)

// DarkComet derives the RC4 key from its version tag; try the known ones.
var rc4Keys = []string{
	"#KCMDDC51#-890",
	"#KCMDDC5#-890",
	"#KCMDDC42#-890",
	"#KCMDDC4#-890",
}

const (
	beginMarker = "#BEGIN DARKCOMET DATA --"
	resName     = "DCDATA"
)

// Config holds the fields of the decrypted DarkComet configuration.
type Config struct {
	Mutex   string
	SID     string
	NetData string // host:port of the C2 (the "attacker")
	GenCode string
	Install string
	// EDTPATH is the install path relative to the COMBOPATH folder.
	InstallPath string
	KeyName     string // name of the Run registry value
	OfflineKey  string
	Raw         map[string]string
}

// Host returns the C2 host part of NETDATA (before the first ':').
func (c *Config) Host() string {
	host, _, _ := strings.Cut(c.NetData, ":")
	return host
}

// Port returns the C2 port part of NETDATA, or "" if there is none.
func (c *Config) Port() string {
	_, port, _ := strings.Cut(c.NetData, ":")
	return port
}

// Extract reads the file at path and returns its DarkComet configuration.
func Extract(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ExtractBytes(data)
}

// ExtractBytes is Extract for an in-memory PE image.
func ExtractBytes(data []byte) (*Config, error) {
	blob, err := resource(data, resName)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(blob)))
	if err != nil {
		return nil, fmt.Errorf("%s is not hex encoded: %w", resName, err)
	}
	for _, key := range rc4Keys {
		plain, err := decrypt(key, raw)
		if err != nil {
			return nil, err
		}
		if bytes.HasPrefix(plain, []byte(beginMarker)) {
			return parse(string(plain)), nil
		}
	}
	return nil, errors.New("DCDATA did not decrypt with any known DarkComet key")
}

func decrypt(key string, data []byte) ([]byte, error) {
	c, err := rc4.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}

// parse turns "KEY={value}" lines into a Config.
func parse(text string) *Config {
	c := &Config{Raw: map[string]string{}}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, "={")
		if !ok || !strings.HasSuffix(val, "}") {
			continue
		}
		c.Raw[key] = strings.TrimSuffix(val, "}")
	}
	c.Mutex = c.Raw["MUTEX"]
	c.SID = c.Raw["SID"]
	c.NetData = c.Raw["NETDATA"]
	c.GenCode = c.Raw["GENCODE"]
	c.Install = c.Raw["INSTALL"]
	c.InstallPath = c.Raw["EDTPATH"]
	c.KeyName = c.Raw["KEYNAME"]
	c.OfflineKey = c.Raw["OFFLINEK"]
	return c
}

// resource walks the PE resource tree and returns the data of the leaf that
// sits under a *named* entry called name (e.g. RT_RCDATA -> "DCDATA" -> lang).
func resource(image []byte, name string) ([]byte, error) {
	f, err := pe.NewFile(bytes.NewReader(image))
	if err != nil {
		return nil, fmt.Errorf("not a PE file: %w", err)
	}
	defer f.Close()

	var rsrc *pe.Section
	for _, s := range f.Sections {
		if s.Name == ".rsrc" {
			rsrc = s
			break
		}
	}
	if rsrc == nil {
		return nil, errors.New("no .rsrc section")
	}
	sec, err := rsrc.Data()
	if err != nil {
		return nil, err
	}

	w := &walker{sec: sec, base: rsrc.VirtualAddress, image: f, want: name}
	if !w.dir(0, false, 0) {
		return nil, fmt.Errorf("resource %q not found", name)
	}
	return w.out, nil
}

type walker struct {
	sec   []byte
	base  uint32 // RVA of the .rsrc section
	image *pe.File
	want  string
	out   []byte
}

func (w *walker) u16(off uint32) (uint16, bool) {
	if uint64(off)+2 > uint64(len(w.sec)) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(w.sec[off:]), true
}

func (w *walker) u32(off uint32) (uint32, bool) {
	if uint64(off)+4 > uint64(len(w.sec)) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(w.sec[off:]), true
}

// entryName decodes a named resource entry (high bit set = offset to a
// length-prefixed UTF-16 string).
func (w *walker) entryName(v uint32) string {
	off := v & 0x7fffffff
	n, ok := w.u16(off)
	if !ok || uint64(off)+2+uint64(n)*2 > uint64(len(w.sec)) {
		return ""
	}
	u := make([]uint16, n)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(w.sec[off+2+uint32(i)*2:])
	}
	return string(utf16.Decode(u))
}

// dir walks the directory at off. matched is true once we are underneath the
// wanted named entry. depth guards against malformed, looping trees.
func (w *walker) dir(off uint32, matched bool, depth int) bool {
	if depth > 4 {
		return false
	}
	named, ok1 := w.u16(off + 12)
	ids, ok2 := w.u16(off + 14)
	if !ok1 || !ok2 {
		return false
	}
	for i := uint32(0); i < uint32(named)+uint32(ids); i++ {
		nameOrID, ok1 := w.u32(off + 16 + i*8)
		target, ok2 := w.u32(off + 20 + i*8)
		if !ok1 || !ok2 {
			return false
		}
		m := matched
		if nameOrID&0x80000000 != 0 && strings.EqualFold(w.entryName(nameOrID), w.want) {
			m = true
		}
		if target&0x80000000 != 0 {
			if w.dir(target&0x7fffffff, m, depth+1) {
				return true
			}
			continue
		}
		if m && w.leaf(target) {
			return true
		}
	}
	return false
}

// leaf reads an IMAGE_RESOURCE_DATA_ENTRY and copies out its bytes.
func (w *walker) leaf(off uint32) bool {
	rva, ok1 := w.u32(off)
	size, ok2 := w.u32(off + 4)
	if !ok1 || !ok2 || rva < w.base {
		return false
	}
	start := rva - w.base
	if uint64(start)+uint64(size) > uint64(len(w.sec)) {
		return false
	}
	w.out = w.sec[start : start+size]
	return true
}
