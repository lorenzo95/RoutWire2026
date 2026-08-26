package mesh

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Spoke persistence. A hub owns the set of agent-less "spoke" names it keeps
// alive in the DHT; this set is persisted so a hub restart doesn't orphan its
// phones. The file is a newline-separated list of normalized names.

// LoadSpokes reads the spoke set from path (missing file = empty set).
func LoadSpokes(path string) (map[string]bool, error) {
	out := map[string]bool{}
	if path == "" {
		return out, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if n := NormalizeName(strings.TrimSpace(ln)); n != "" {
			out[n] = true
		}
	}
	return out, nil
}

// SaveSpokes atomically writes the spoke set to path.
func SaveSpokes(path string, spokes map[string]bool) error {
	if path == "" {
		return nil
	}
	names := make([]string, 0, len(spokes))
	for n := range spokes {
		names = append(names, n)
	}
	sort.Strings(names)
	data := []byte(strings.Join(names, "\n"))
	if len(names) > 0 {
		data = append(data, '\n')
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// AddSpoke registers name in the persisted spoke set (idempotent).
func AddSpoke(path, name string) error {
	name = NormalizeName(name)
	if name == "" {
		return nil
	}
	set, err := LoadSpokes(path)
	if err != nil {
		return err
	}
	if set[name] {
		return nil
	}
	set[name] = true
	return SaveSpokes(path, set)
}

// RemoveSpoke unregisters name from the persisted spoke set (idempotent).
func RemoveSpoke(path, name string) error {
	name = NormalizeName(name)
	set, err := LoadSpokes(path)
	if err != nil {
		return err
	}
	if !set[name] {
		return nil
	}
	delete(set, name)
	return SaveSpokes(path, set)
}
