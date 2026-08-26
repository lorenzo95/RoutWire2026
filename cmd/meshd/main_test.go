package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"routewire/internal/config"
)

func TestRenderConfigRoundTrip(t *testing.T) {
	in := &config.MeshConfig{
		PSK:      "s3cret/psk+",
		Name:     "alpha",
		IFace:    "wg0",
		CIDR:     "10.55.0.0/16",
		Port:     51821,
		MTU:      1380,
		Poll:     "20s",
		Stale:    "2m",
		Stun:     []string{"stun.a:1", "stun.b:2"},
		Proxies:  []string{"https://p1"},
		Backend:  "mock",
		Announce: []string{"192.168.50.0/24"},
		DryRun:   true,
	}
	path := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(path, renderConfigYAML(in), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := config.LoadMeshConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	in.Stale = got.Stale
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, in)
	}
}

func TestRenderConfigBakesDefaultsForEmptyLists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(path, renderConfigYAML(&config.MeshConfig{CIDR: "10.99.0.0/16"}), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := config.LoadMeshConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Stun, defaultStunServers) {
		t.Fatalf("stun defaults not baked: %v", got.Stun)
	}
	if !reflect.DeepEqual(got.Proxies, config.DefaultProxies) {
		t.Fatalf("proxy defaults not baked: %v", got.Proxies)
	}
	if len(got.Announce) != 0 || got.PSK != "" || got.DryRun {
		t.Fatalf("unexpected values parsed back: %+v", got)
	}
}

func TestExpandSubcommand(t *testing.T) {
	cases := [][]string{
		{"init", "-name", "a"},
		{"export", "-remote", "p1"},
		{"stop"},
		{"-psk", "x"},
	}
	wantFlag := []string{"-init", "-export", "-stop", ""}
	for i, c := range cases {
		got := expandSubcommand(c)
		if wantFlag[i] == "" {
			if !reflect.DeepEqual(got, c) {
				t.Fatalf("case %d: passthrough broken: %v", i, got)
			}
			continue
		}
		if got[0] != wantFlag[i] || len(got) != len(c) {
			t.Fatalf("case %d: got %v want leading %s", i, got, wantFlag[i])
		}
	}
}

func TestExpandSubcommandAnywhere(t *testing.T) {
	// The subcommand must be recognized even when flags precede it, otherwise
	// "meshd -config file.yaml peek" silently starts the daemon.
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"-config", "file.yaml", "peek"}, "-peek"},
		{[]string{"-config", "file.yaml", "init", "-name", "a"}, "-init"},
		{[]string{"-config", "file.yaml", "export", "-remote", "p1"}, "-export"},
		{[]string{"-config", "file.yaml", "stop"}, "-stop"},
		// a node literally named "peek" must NOT be treated as a subcommand
		{[]string{"-name", "peek"}, ""},
		{[]string{"-config", "file.yaml", "-name", "peek"}, ""},
	}
	for _, c := range cases {
		got := expandSubcommand(c.in)
		if c.want == "" {
			if !reflect.DeepEqual(got, c.in) {
				t.Fatalf("input %v: expected passthrough, got %v", c.in, got)
			}
			continue
		}
		if got[0] != c.want || len(got) != len(c.in) {
			t.Fatalf("input %v: got %v want leading %s", c.in, got, c.want)
		}
	}
}
