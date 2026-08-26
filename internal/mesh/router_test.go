package mesh

import (
	"errors"
	"os/exec"
	"testing"
)

func TestNewLinuxRouterWithoutIptables(t *testing.T) {
	if _, err := exec.LookPath("iptables"); err == nil {
		t.Skip("iptables present; nothing to test")
	}
	_, err := NewLinuxRouter("wgtest0", 51820)
	if !errors.Is(err, ErrNoIptables) {
		t.Fatalf("want ErrNoIptables, got %v", err)
	}
}
