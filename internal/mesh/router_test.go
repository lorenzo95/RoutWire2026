package mesh

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestForwardingAlreadyEnabledNeedsNoWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ip_forward")
	if err := os.WriteFile(path, []byte("1\n"), 0o444); err != nil { // read-only: any write attempt fails loudly
		t.Fatal(err)
	}
	old := ipForwardPath
	ipForwardPath = path
	defer func() { ipForwardPath = old }()

	r := &linuxRouter{}
	if err := r.Forwarding(); err != nil {
		t.Fatalf("already-enabled forwarding must succeed silently, got %v", err)
	}
}

func TestForwardingEnablesWhenOff(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ip_forward")
	if err := os.WriteFile(path, []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := ipForwardPath
	ipForwardPath = path
	defer func() { ipForwardPath = old }()

	r := &linuxRouter{}
	if err := r.Forwarding(); err != nil {
		t.Fatalf("enable failed: %v", err)
	}
	b, _ := os.ReadFile(path)
	if strings.TrimSpace(string(b)) != "1" {
		t.Fatalf("forwarding not enabled: %q", b)
	}
	// idempotent
	if err := r.Forwarding(); err != nil {
		t.Fatalf("second call must be a no-op: %v", err)
	}
}

func TestForwardingFailsWhenUnavailable(t *testing.T) {
	// A directory defeats writes even for root (permission bits don't —
	// the test suite may run as root).
	dir := t.TempDir()
	path := filepath.Join(dir, "is-a-dir")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	old := ipForwardPath
	ipForwardPath = path
	defer func() { ipForwardPath = old }()

	r := &linuxRouter{}
	if err := r.Forwarding(); err == nil {
		t.Fatal("unwritable sysctl must error")
	}
}

func TestNewLinuxRouterWithoutIptables(t *testing.T) {
	if _, err := exec.LookPath("iptables"); err == nil {
		t.Skip("iptables present; nothing to test")
	}
	_, err := NewLinuxRouter("wgtest0", 51820)
	if !errors.Is(err, ErrNoIptables) {
		t.Fatalf("want ErrNoIptables, got %v", err)
	}
}
