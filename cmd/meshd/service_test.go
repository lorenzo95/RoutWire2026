package main

import (
	"strings"
	"testing"
)

func TestSystemdUnitTemplate(t *testing.T) {
	u := systemdUnit("/usr/local/bin/meshd", "/etc/meshd.yaml")
	for _, want := range []string{
		"[Unit]", "[Service]", "[Install]",
		"ExecStart=/usr/local/bin/meshd -config /etc/meshd.yaml",
		"Restart=always",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, want) {
			t.Fatalf("unit missing %q:\n%s", want, u)
		}
	}
}

func TestSysvScriptTemplate(t *testing.T) {
	s := sysvScript("/usr/local/bin/meshd", "/etc/meshd.yaml")
	for _, want := range []string{
		"#!/bin/sh",
		"DAEMON=/usr/local/bin/meshd",
		"CONFIG=/etc/meshd.yaml",
		"Default-Start:",
		"start-stop-daemon",
		"nohup", // portable fallback
		"case \"$1\" in",
		"esac",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("script missing %q:\n%s", want, s)
		}
	}
}

func TestCheckServiceArgs(t *testing.T) {
	if err := checkServiceArgs(false, false, ""); err == nil {
		t.Fatal("no action must fail")
	}
	if err := checkServiceArgs(true, true, ""); err == nil {
		t.Fatal("both actions must fail")
	}
	if err := checkServiceArgs(true, false, "openrc"); err == nil {
		t.Fatal("unknown init system must fail")
	}
	for _, combo := range []struct{ i, u bool }{{true, false}, {false, true}} {
		for _, m := range []string{"", "auto", "systemd", "sysvinit"} {
			if err := checkServiceArgs(combo.i, combo.u, m); err != nil {
				t.Fatalf("valid combo rejected (i=%v u=%v m=%q): %v", combo.i, combo.u, m, err)
			}
		}
	}
}

func TestDetectInitSystemReturnsKnown(t *testing.T) {
	got := detectInitSystem()
	if got != "systemd" && got != "sysvinit" {
		t.Fatalf("unexpected init system %q", got)
	}
}
