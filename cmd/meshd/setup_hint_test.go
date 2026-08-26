package main

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

func TestSetupHint(t *testing.T) {
	wrap := func(err error) error { return errors.Join(errors.New("create wgmesh0: "), err) }

	if h := setupHint(wrap(syscall.EOPNOTSUPP)); !strings.Contains(h, "modprobe wireguard") {
		t.Fatalf("EOPNOTSUPP hint missing kernel advice: %q", h)
	}
	if h := setupHint(wrap(syscall.EPERM)); !strings.Contains(h, "NET_ADMIN") {
		t.Fatalf("EPERM hint missing capability advice: %q", h)
	}
	if h := setupHint(wrap(syscall.EEXIST)); !strings.Contains(h, "meshd stop") {
		t.Fatalf("EEXIST hint missing cleanup advice: %q", h)
	}
	// substring fallback (netlink libs may wrap errnos as plain text)
	if h := setupHint(errors.New("attribute not supported")); !strings.Contains(h, "kernel has no WireGuard") {
		t.Fatalf("substring fallback failed: %q", h)
	}
	if h := setupHint(errors.New("something else")); h != "" {
		t.Fatalf("unrelated errors must get no hint, got %q", h)
	}
}
