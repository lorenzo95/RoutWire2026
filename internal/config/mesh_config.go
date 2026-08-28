package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// MeshConfig is the meshd configuration file schema. The same parser handles
// YAML and JSON (JSON is valid YAML).
type MeshConfig struct {
	PSK      string   `yaml:"psk,omitempty"`
	Name     string   `yaml:"name,omitempty"`
	IFace    string   `yaml:"iface,omitempty"`
	CIDR     string   `yaml:"cidr,omitempty"`
	Port     int      `yaml:"port,omitempty"`
	MTU      int      `yaml:"mtu,omitempty"`
	Poll     string   `yaml:"poll,omitempty"`
	Stale    string   `yaml:"stale,omitempty"`
	Stun     []string `yaml:"stun,omitempty"`
	Proxies  []string `yaml:"proxies,omitempty"`
	Backend  string   `yaml:"backend,omitempty"`
	Announce []string `yaml:"announce,omitempty"`
	DryRun   bool     `yaml:"dry_run,omitempty"`
	FirewallSelfHeal bool `yaml:"firewall_selfheal,omitempty"`
}

// LoadMeshConfig reads a config file strictly (must exist and parse).
func LoadMeshConfig(path string) (*MeshConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c MeshConfig
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// ResolveMesh merges configuration layers: defaults < file < env < flags.
// `flags` must contain ONLY explicitly-set flags (see flag.Visit).
func ResolveMesh(defs *MeshConfig, file *MeshConfig, env map[string]string, flags map[string]string) *MeshConfig {
	out := &MeshConfig{}
	if defs != nil {
		*out = *defs
	}
	if file != nil {
		mergeMeshInto(out, file)
	}
	if v, ok := env["MESH_PSK"]; ok && !flagsSet(flags, "psk") {
		out.PSK = v
	}
	if v, ok := env["MESH_NAME"]; ok && !flagsSet(flags, "name") {
		out.Name = v
	}
	if flags != nil {
		mergeMeshInto(out, flagsToMesh(flags))
	}
	return out
}

func mergeMeshInto(dst, src *MeshConfig) {
	if src.PSK != "" {
		dst.PSK = src.PSK
	}
	if src.Name != "" {
		dst.Name = src.Name
	}
	if src.IFace != "" {
		dst.IFace = src.IFace
	}
	if src.CIDR != "" {
		dst.CIDR = src.CIDR
	}
	if src.Port != 0 {
		dst.Port = src.Port
	}
	if src.MTU != 0 {
		dst.MTU = src.MTU
	}
	if src.Poll != "" {
		dst.Poll = src.Poll
	}
	if src.Stale != "" {
		dst.Stale = src.Stale
	}
	if len(src.Stun) > 0 {
		dst.Stun = src.Stun
	}
	if len(src.Proxies) > 0 {
		dst.Proxies = src.Proxies
	}
	if src.Backend != "" {
		dst.Backend = src.Backend
	}
	if len(src.Announce) > 0 {
		dst.Announce = src.Announce
	}
	if src.DryRun {
		dst.DryRun = true
	}
}

func flagsSet(flags map[string]string, name string) bool {
	_, ok := flags[name]
	return ok
}

func flagsToMesh(flags map[string]string) *MeshConfig {
	m := &MeshConfig{}
	if v, ok := flags["psk"]; ok {
		m.PSK = v
	}
	if v, ok := flags["name"]; ok {
		m.Name = v
	}
	if v, ok := flags["iface"]; ok {
		m.IFace = v
	}
	if v, ok := flags["cidr"]; ok {
		m.CIDR = v
	}
	if v, ok := flags["port"]; ok {
		m.Port = atoiOrZero(v)
	}
	if v, ok := flags["mtu"]; ok {
		m.MTU = atoiOrZero(v)
	}
	if v, ok := flags["poll"]; ok {
		m.Poll = v
	}
	if v, ok := flags["stale"]; ok {
		m.Stale = v
	}
	if v, ok := flags["stun"]; ok {
		m.Stun = splitComma(v)
	}
	if v, ok := flags["proxies"]; ok {
		m.Proxies = splitComma(v)
	}
	if v, ok := flags["announce"]; ok {
		m.Announce = splitComma(v)
	}
	if v, ok := flags["backend"]; ok {
		m.Backend = v
	}
	if v, ok := flags["dry-run"]; ok && truthy(v) {
		m.DryRun = true
	}
	return m
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := s[start:i]
			if part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	return out
}

func atoiOrZero(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func truthy(s string) bool {
	switch s {
	case "1", "true", "TRUE", "True", "yes":
		return true
	}
	return false
}
