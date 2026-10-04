package sessioninit

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

// rootHashFromCmdline returns the verity root hash on the kernel command
// line. The command line is part of the measured kernel image, so this is
// the one value that says which root file system this guest may run.
func rootHashFromCmdline(cmdline string) ([]byte, error) {
	var value string
	for _, field := range strings.Fields(cmdline) {
		if v, ok := strings.CutPrefix(field, "roothash="); ok {
			value = v
		}
	}
	if value == "" {
		return nil, errors.New("no roothash= on the kernel command line")
	}
	hash, err := hex.DecodeString(value)
	if err != nil || (len(hash) != 32 && len(hash) != 48 && len(hash) != 64) {
		return nil, fmt.Errorf("roothash=%s is not a SHA-256, SHA-384 or SHA-512 digest in hex", value)
	}
	return hash, nil
}

// stateDirs reads the image's lists of directories that get a writable
// overlay: one path a line, relative to the root, in files that are read in
// name order. Everything else on the root stays read-only.
func stateDirs(files map[string][]byte) ([]string, error) {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var dirs []string
	seen := map[string]bool{}
	for _, name := range names {
		for _, line := range strings.Split(string(files[name]), "\n") {
			dir := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
			if dir == "" || strings.HasPrefix(dir, "#") {
				continue
			}
			clean := path.Clean("/" + dir)[1:]
			if clean == "" || clean != strings.Trim(dir, "/") || strings.ContainsAny(dir, ",:\\") {
				// A comma or a colon would end the path inside the overlay's
				// mount options.
				return nil, fmt.Errorf("%s lists %q, which is no plain path below the root", name, dir)
			}
			if !seen[clean] {
				seen[clean] = true
				dirs = append(dirs, clean)
			}
		}
	}
	if len(dirs) == 0 {
		return nil, errors.New("the image lists no directory to keep writable state in")
	}
	return dirs, nil
}

// setting is one line of a sysctl.d file.
type setting struct {
	// Key is the path below /proc/sys, with slashes.
	Key, Value string
	// Optional settings may fail to apply: their line began with a dash.
	Optional bool
}

// sysctlSettings merges sysctl.d directories the way systemd-sysctl does: a
// file in a later directory replaces the file of the same name in an earlier
// one, the files apply in name order, and a later line wins.
func sysctlSettings(dirs []map[string][]byte) ([]setting, error) {
	merged := map[string][]byte{}
	for _, dir := range dirs {
		for name, data := range dir {
			if strings.HasSuffix(name, ".conf") {
				merged[name] = data
			}
		}
	}
	names := make([]string, 0, len(merged))
	for name := range merged {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []setting
	for _, name := range names {
		for n, line := range strings.Split(string(merged[name]), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line[0] == '#' || line[0] == ';' {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				return nil, fmt.Errorf("%s line %d: no value", name, n+1)
			}
			s := setting{Key: strings.TrimSpace(key), Value: strings.TrimSpace(value)}
			if rest, optional := strings.CutPrefix(s.Key, "-"); optional {
				s.Key, s.Optional = strings.TrimSpace(rest), true
			}
			// Either separator names the same file. A key written with
			// slashes may hold dots of its own, an interface's name for one.
			if !strings.Contains(s.Key, "/") {
				s.Key = strings.ReplaceAll(s.Key, ".", "/")
			}
			if s.Key == "" || strings.Contains("/"+s.Key+"/", "/../") || strings.HasPrefix(s.Key, "/") {
				return nil, fmt.Errorf("%s line %d: key %q", name, n+1, key)
			}
			out = append(out, s)
		}
	}
	return out, nil
}

// maxBootConfig bounds the image's description of what the init runs.
const maxBootConfig = 64 * 1024

// bootConfig is the image's own description of what the init runs once the
// root is up. It sits on the verity root, so the root hash covers it.
type bootConfig struct {
	// Steps run one after another and each must exit 0: the launch files
	// are staged and the packet filter loaded before the service starts.
	Steps [][]string `json:"steps"`
	// Service is the guest's one long-running program. When it exits, for
	// whatever reason, the guest ends.
	Service []string `json:"service"`
	// Hostname is the guest's host name.
	Hostname string `json:"hostname,omitempty"`
}

func parseBootConfig(data []byte) (*bootConfig, error) {
	if len(data) == 0 || len(data) > maxBootConfig {
		return nil, fmt.Errorf("boot configuration of %d bytes", len(data))
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg bootConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("boot configuration: %w", err)
	}
	if dec.More() {
		return nil, errors.New("boot configuration: trailing data")
	}
	for i, argv := range append(append([][]string{}, cfg.Steps...), cfg.Service) {
		if len(argv) == 0 || !path.IsAbs(argv[0]) {
			return nil, fmt.Errorf("boot configuration: command %d names no absolute path", i+1)
		}
	}
	return &cfg, nil
}
