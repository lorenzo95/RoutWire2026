package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveMeshPrecedence(t *testing.T) {
	defs := &MeshConfig{CIDR: "10.99.0.0/16", Port: 51820, Backend: "opendht"}
	file := &MeshConfig{Name: "from-file", Port: 9999, Stun: []string{"stun.file:1"}, PSK: "file-psk"}
	flags := map[string]string{"port": "7777"}

	got := ResolveMesh(defs, file, map[string]string{"MESH_PSK": "env-psk"}, flags)

	if got.CIDR != "10.99.0.0/16" {
		t.Fatalf("default lost: %q", got.CIDR)
	}
	if got.PSK != "env-psk" {
		t.Fatalf("env must beat file for psk (flag unset): got %q", got.PSK)
	}
	if got.Name != "from-file" {
		t.Fatalf("file name lost: %q", got.Name)
	}
	if got.Port != 7777 {
		t.Fatalf("flag must beat everything: %d", got.Port)
	}
	if len(got.Stun) != 1 || got.Stun[0] != "stun.file:1" {
		t.Fatalf("file stun list lost: %v", got.Stun)
	}
}

func TestResolveMeshEnvBeatsFileForPSK(t *testing.T) {
	file := &MeshConfig{PSK: "file-psk", Name: "n"}
	got := ResolveMesh(nil, file, map[string]string{"MESH_PSK": "env-psk"}, nil)
	if got.PSK != "env-psk" {
		t.Fatalf("env should beat file for psk, got %q", got.PSK)
	}
}

func TestLoadMeshConfigHandlesJSONAndYAML(t *testing.T) {
	dir := t.TempDir()

	jsonPath := filepath.Join(dir, "m.json")
	jsonBody := `{"psk":"abc","name":"node1","announce":["192.168.50.0/24"],"dry_run":true}`
	if err := os.WriteFile(jsonPath, []byte(jsonBody), 0o600); err != nil {
		t.Fatal(err)
	}
	jc, err := LoadMeshConfig(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if jc.PSK != "abc" || jc.Name != "node1" || !jc.DryRun || len(jc.Announce) != 1 {
		t.Fatalf("json parse wrong: %+v", jc)
	}

	yamlPath := filepath.Join(dir, "m.yaml")
	yamlBody := "psk: abc\nname: node2\nstun:\n  - a:1\n  - b:2\n"
	if err := os.WriteFile(yamlPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatal(err)
	}
	yc, err := LoadMeshConfig(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	if yc.Name != "node2" || len(yc.Stun) != 2 {
		t.Fatalf("yaml parse wrong: %+v", yc)
	}
}
