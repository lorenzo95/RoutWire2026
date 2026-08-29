package mesh

import (
	"bytes"
	"errors"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
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
	_, err := NewLinuxRouter("wgtest0", 51820, false, nil)
	if !errors.Is(err, ErrNoIptables) {
		t.Fatalf("want ErrNoIptables, got %v", err)
	}
}

// shimBinaries drops fake iptables/ip6tables into a temp dir on PATH. The
// fakes log every invocation and fail -C probes (rule "not present") so
// openPort always takes the insert path.
func shimBinaries(t *testing.T, withIP6 bool) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	state := filepath.Join(dir, "state")
	names := []string{iptablesBin}
	if withIP6 {
		names = append(names, ip6tablesBin)
	}
	// A stateful mini-iptables: -I adds to the state, -C checks presence,
	// -D removes. This lets both openPort (needs -C to fail for absent
	// rules) and delIPTRule (needs -C to succeed for existing rules) behave
	// like the real thing in one shim. The verb is the first -[IACD] token
	// (the -t table flag may precede it).
	script := "#!/bin/sh\n" +
		"echo \"$0 $@\" >> " + log + "\n" +
		"verb=\"\"\n" +
		"for a in \"$@\"; do case \"$a\" in -[IACD]) verb=\"$a\"; break;; esac; done\n" +
		"norm=$(echo \"$@\" | sed -E 's/^-t [^ ]+ //; s/^-[IACD] //; s/^([A-Za-z0-9]+) 1 /\\1 /')\n" +
		"case \"$verb\" in\n" +
		"  -I) echo \"$norm\" >> " + state + "; exit 0;;\n" +
		"  -C) grep -qxF \"$norm\" " + state + " 2>/dev/null && exit 0 || exit 1;;\n" +
		"  -D) grep -vxF \"$norm\" " + state + " > " + state + ".n 2>/dev/null; mv " + state + ".n " + state + "; exit 0;;\n" +
		"esac\nexit 0\n"
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	return log
}

// (the dual-family open/Close cycle is covered by the Live tests on real kernels)

func TestOpenPortDegradesToV4WithoutIP6tables(t *testing.T) {
	log := shimBinaries(t, false)

	r := &linuxRouter{iface: "wgtest0", port: 51822, added: map[string]bool{}, hasIP6: false}
	if err := r.openPort(); err != nil {
		t.Fatalf("openPort without ip6tables must still open v4, got %v", err)
	}
	b, _ := os.ReadFile(log)
	calls := string(b)
	if strings.Count(calls, "-I INPUT 1") != 1 || strings.Contains(calls, ip6tablesBin) {
		t.Fatalf("v4-only host must insert exactly one rule and never call ip6tables:\n%s", calls)
	}
}

// captureLog returns a logger plus a func that yields everything it printed.
func captureLog(t *testing.T) (*log.Logger, func() string) {
	t.Helper()
	var buf bytes.Buffer
	l := log.New(&buf, "", 0)
	return l, buf.String
}

// Live remediation against the real kernel: a foreign inet chain with a
// drop policy and no rule for our port gets an accept inserted (tagged via
// rule userdata), and Close removes it again. Skips without root or netlink.
// The hostile chain is created atomically together with a catch-all accept
// so its drop policy can never sever live traffic mid-test.
func TestRouterRemediatesForeignDropChainLive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for netlink")
	}
	conn, err := nftables.New()
	if err != nil {
		t.Skipf("no netlink: %v", err)
	}
	hook, prio, policy := *nftables.ChainHookInput, *nftables.ChainPriorityFilter, nftables.ChainPolicyDrop
	tbl := &nftables.Table{Name: "routewire-test", Family: nftables.TableFamilyINet}
	ch := &nftables.Chain{
		Name: "input", Table: tbl,
		Hooknum: &hook, Priority: &prio, Policy: &policy,
		Type: nftables.ChainTypeFilter,
	}
	conn.AddTable(tbl)
	conn.AddChain(ch)
	// Catch-all accept in the same atomic batch: the chain still counts as
	// blocking (drop policy, no rule for our port) but harmless to traffic.
	conn.AddRule(&nftables.Rule{Table: tbl, Chain: ch, Exprs: []expr.Any{
		&expr.Verdict{Kind: expr.VerdictAccept},
	}})
	if err := conn.Flush(); err != nil {
		t.Skipf("cannot create test chain: %v", err)
	}
	defer func() {
		c, err := nftables.New()
		if err == nil {
			c.DelTable(tbl)
			c.Flush()
		}
	}()

	l, printed := captureLog(t)
	r := &linuxRouter{iface: "wgtest0", port: 51999, added: map[string]bool{}, hasIP6: false, selfheal: true}
	r.applyInputSelfHeal(l, 51999)
	if len(r.taggedChains) == 0 {
		t.Fatalf("drop-policy chain lacking our port must be remediated, log: %s", printed())
	}

	// The inserted rule is tagged and visible via netlink.
	rules, err := conn.GetRules(tbl, ch)
	if err != nil {
		t.Fatalf("get rules: %v", err)
	}
	tagged := 0
	for _, rule := range rules {
		if string(rule.UserData) == nftComment {
			tagged++
		}
	}
	if tagged != 1 {
		t.Fatalf("want exactly one tagged accept for udp/51999, got %d", tagged)
	}
	if out := printed(); !strings.Contains(out, "opened udp/51999") {
		t.Fatalf("successful remediation must be logged, got: %s", out)
	}

	// Close removes the tagged rule, leaves the rest of the chain alone.
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	rules, err = conn.GetRules(tbl, ch)
	if err != nil {
		t.Fatalf("get rules after close: %v", err)
	}
	for _, rule := range rules {
		if string(rule.UserData) == nftComment {
			t.Fatal("close must remove our remediation rule")
		}
	}
}

// Forward-hook variant: a drop-policy forward chain gets the tagged
// iifname/oifname pair when the router enables forwarding, and Close
// removes them. Same atomic-safety trick as the input test.
func TestRouterRemediatesForwardChainLive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for netlink")
	}
	conn, err := nftables.New()
	if err != nil {
		t.Skipf("no netlink: %v", err)
	}
	hook, prio, policy := *nftables.ChainHookForward, *nftables.ChainPriorityFilter, nftables.ChainPolicyDrop
	tbl := &nftables.Table{Name: "routewire-fwdtest", Family: nftables.TableFamilyINet}
	ch := &nftables.Chain{
		Name: "forward", Table: tbl,
		Hooknum: &hook, Priority: &prio, Policy: &policy,
		Type: nftables.ChainTypeFilter,
	}
	conn.AddTable(tbl)
	conn.AddChain(ch)
	conn.AddRule(&nftables.Rule{Table: tbl, Chain: ch, Exprs: []expr.Any{
		&expr.Verdict{Kind: expr.VerdictAccept},
	}})
	if err := conn.Flush(); err != nil {
		t.Skipf("cannot create test chain: %v", err)
	}
	defer func() {
		c, err := nftables.New()
		if err == nil {
			c.DelTable(tbl)
			c.Flush()
		}
	}()

	l, printed := captureLog(t)
	r := &linuxRouter{iface: "rwtest0", port: 51999, added: map[string]bool{}, hasIP6: false, selfheal: true, log: l}
	if err := r.Forwarding(); err != nil {
		t.Fatalf("forwarding: %v", err)
	}
	if len(r.taggedChains) == 0 {
		t.Fatalf("drop-policy forward chain must be remediated, log: %s", printed())
	}
	rules, err := conn.GetRules(tbl, ch)
	if err != nil {
		t.Fatalf("get rules: %v", err)
	}
	tagged := 0
	for _, rule := range rules {
		if string(rule.UserData) == nftComment {
			tagged++
		}
	}
	if tagged != 2 {
		t.Fatalf("want iifname+oifname tagged rules, got %d", tagged)
	}
	if out := printed(); !strings.Contains(out, "opened forwarding for") {
		t.Fatalf("successful forward remediation must be logged, got: %s", out)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	rules, err = conn.GetRules(tbl, ch)
	if err != nil {
		t.Fatalf("get rules after close: %v", err)
	}
	for _, rule := range rules {
		if string(rule.UserData) == nftComment {
			t.Fatal("close must remove the forward remediation rules")
		}
	}
}

func TestWarnBlockedFromSaveFlagsLegacyDrop(t *testing.T) {
	l, printed := captureLog(t)
	dump := `*filter
:INPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
COMMIT
*nat
:POSTROUTING ACCEPT [0:0]
COMMIT`
	warnBlockedFromSave(l, "iptables-save", "51822", dump)
	out := printed()
	if !strings.Contains(out, `"INPUT"`) || !strings.Contains(out, "51822") {
		t.Fatalf("legacy DROP policy without our port must be reported, got: %s", out)
	}

	// An allow rule for the port silences the warning.
	dump = `*filter
:INPUT DROP [0:0]
-A INPUT -p udp --dport 51822 -j ACCEPT
COMMIT`
	l, printed = captureLog(t)
	warnBlockedFromSave(l, "iptables-save", "51822", dump)
	if out := printed(); out != "" {
		t.Fatalf("legacy allowlisted port must not warn, got: %s", out)
	}
}

// Docker sets FORWARD policy DROP on every host — that must never warn.
func TestWarnBlockedFromSaveIgnoresForwardPolicy(t *testing.T) {
	l, printed := captureLog(t)
	dump := `*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
-A FORWARD -j DOCKER-USER
COMMIT`
	warnBlockedFromSave(l, "ip6tables-save", "51822", dump)
	if out := printed(); out != "" {
		t.Fatalf("FORWARD drop policy is not our business, got: %s", out)
	}
}

// The Pangolin scenario, end to end: a foreign inet chain with a drop policy
// that lacks our port gets an accept inserted (tagged via userdata) and the
// insertion is undone on Close. Exercised live by
// TestRouterRemediatesForeignDropChain above.

func TestMentionsPortWholeField(t *testing.T) {
	if !mentionsPort("udp dport { 443, 21820, 51820 } accept", "51820") {
		t.Fatal("set literal member must match")
	}
	if mentionsPort("udp dport { 443, 21820, 51820 } accept", "5182") {
		t.Fatal("partial port must not match")
	}
	if !mentionsPort("-p udp --dport 51822 -j ACCEPT", "51822") {
		t.Fatal("plain dport must match")
	}
}

// Live end-to-end tests against REAL iptables. These exist because the
// fake-binary unit tests verify that cleanup *calls* iptables, not that the
// calls work — the stop-cleanup shipped broken twice before this existed.
// They need root and the iptables binary (run inside the meshd container or
// on a host with iptables installed; they skip elsewhere).

func liveSkip(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("no iptables binary")
	}
}

func TestAnnounceNATLive(t *testing.T) {
	liveSkip(t)
	_, overlay, _ := net.ParseCIDR("10.99.0.0/16")
	_, lan, _ := net.ParseCIDR("192.168.50.0/24")
	r := &linuxRouter{iface: "wgtest0", added: map[string]bool{}, announceNAT: map[string]string{}}

	clean := func() {
		exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", overlay.String(), "-d", lan.String(), "-j", "MASQUERADE").Run()
		exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", overlay.String(), "-d", lan.String(), "-m", "comment", "--comment", iptComment, "-j", "MASQUERADE").Run()
	}
	clean()
	t.Cleanup(clean)

	if err := r.AnnounceNAT(overlay, []net.IPNet{*lan}); err != nil {
		t.Fatalf("announce: %v", err)
	}
	out, _ := exec.Command("iptables-save", "-t", "nat").CombinedOutput()
	if !strings.Contains(string(out), "-d "+lan.String()) || !strings.Contains(string(out), iptComment) {
		t.Fatalf("tagged rule missing after announce:\n%s", out)
	}

	// Reconciling to empty removes the rule for real.
	if err := r.AnnounceNAT(overlay, nil); err != nil {
		t.Fatalf("de-announce: %v", err)
	}
	out, _ = exec.Command("iptables-save", "-t", "nat").CombinedOutput()
	if strings.Contains(string(out), "-d "+lan.String()) {
		t.Fatalf("rule must be gone after de-announce:\n%s", out)
	}
}

// The exact laptop scenario: a tagged meshd rule, an UNTAGGED manual rule
// with the same shape, port accepts — stop removes meshd's, leaves the
// manual one, and a second run stays silent.
func TestCleanupFirewallLive(t *testing.T) {
	liveSkip(t)
	_, overlay, _ := net.ParseCIDR("10.99.0.0/16")
	_, lan, _ := net.ParseCIDR("192.168.1.0/24")
	spoke := net.ParseIP("10.99.9.12")
	lg := log.New(os.Stderr, "", 0)

	plant := func(args ...string) {
		if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			t.Fatalf("plant %v: %v (%s)", args, err, out)
		}
	}
	del := func(args ...string) { exec.Command("iptables", args...).Run() }
	plant("-t", "nat", "-A", "POSTROUTING", "-s", "10.99.9.99/32", "-d", lan.String(), "-m", "comment", "--comment", iptComment, "-j", "MASQUERADE")
	plant("-t", "nat", "-A", "POSTROUTING", "-s", overlay.String(), "-d", lan.String(), "-j", "MASQUERADE") // untagged manual
	plant("-I", "INPUT", "-p", "udp", "--dport", "51999", "-j", "ACCEPT")
	plant("-t", "nat", "-A", "POSTROUTING", "-s", spoke.String()+"/32", "-o", "wgtest0", "-m", "comment", "--comment", iptComment, "-j", "MASQUERADE")
	t.Cleanup(func() {
		del("-t", "nat", "-D", "POSTROUTING", "-s", overlay.String(), "-d", lan.String(), "-j", "MASQUERADE")
		del("-D", "INPUT", "-p", "udp", "--dport", "51999", "-j", "ACCEPT")
	})

	CleanupFirewall(lg, "wgtest0", 51999, overlay, []net.IPNet{*lan}, []net.IP{spoke})

	out, _ := exec.Command("iptables-save").CombinedOutput()
	if strings.Contains(string(out), iptComment) {
		t.Fatalf("tagged rules must all be removed:\n%s", out)
	}
	if !strings.Contains(string(out), "-d "+lan.String()) {
		t.Fatalf("the untagged manual rule is not ours — must survive:\n%s", out)
	}
	if strings.Contains(string(out), "--dport 51999") {
		t.Fatalf("port accept must be removed:\n%s", out)
	}

	// Second run: idempotent, silent.
	var buf bytes.Buffer
	quiet := log.New(&buf, "", 0)
	CleanupFirewall(quiet, "wgtest0", 51999, overlay, []net.IPNet{*lan}, []net.IP{spoke})
	if s := buf.String(); s != "" {
		t.Fatalf("second cleanup on a clean host must be silent, got: %s", s)
	}
}


// Re-running stop against an already-clean host is a silent no-op: absent
// rules delete-fail, the -C probe confirms absence, and nothing warns.
func TestCleanupFirewallIdempotentWhenRulesAbsent(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\ncase \"$*\" in *\"-D \"*|*\"-C \"*) exit 1;; esac\nexit 0\n"
	for _, name := range []string{iptablesBin, ip6tablesBin} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	l, printed := captureLog(t)

	_, overlay, _ := net.ParseCIDR("10.99.0.0/16")
	CleanupFirewall(l, "wgtest0", 51822, overlay, nil, nil)

	if out := printed(); out != "" {
		t.Fatalf("idempotent stop must be silent, got: %s", out)
	}
}

// Tagged NAT rules are swept even when the config no longer mentions the
// announcement — the stop process reads the live ruleset, not the config.
func TestCleanupFirewallSweepsTaggedNAT(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "calls")
	dumpFile := filepath.Join(dir, "dump")
	dump := `*nat
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
-A POSTROUTING -s 10.99.0.0/16 -d 192.168.1.0/24 -m comment --comment routewire-meshd -j MASQUERADE
COMMIT`
	// iptables-save serves the dump; iptables/ip6tables log deletes and pass
	// the -D probes.
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("dump", dump)
	write(iptablesBin, "#!/bin/sh\necho \"$@\" >> "+logFile+"\nexit 0\n")
	write(ip6tablesBin, "#!/bin/sh\necho \"$@\" >> "+logFile+"\nexit 0\n")
	write("iptables-save", "#!/bin/sh\n[ \"$1\" = \"-t\" ] && [ \"$2\" = \"nat\" ] && /bin/cat "+dumpFile+"\nexit 0\n")
	write("ip6tables-save", "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", dir)
	l, _ := captureLog(t)

	_, lan, _ := net.ParseCIDR("192.168.1.0/24")
	CleanupFirewall(l, "wgtest0", 51822, nil, []net.IPNet{*lan}, nil)

	b, _ := os.ReadFile(logFile)
	calls := string(b)
	if !strings.Contains(calls, "-D POSTROUTING -s 10.99.0.0/16 -d 192.168.1.0/24 -m comment --comment routewire-meshd -j MASQUERADE") {
		t.Fatalf("tagged NAT rule must be swept by comment, calls:\n%s", calls)
	}
	if strings.Contains(calls, "172.17.0.0/16") {
		t.Fatalf("untagged foreign masquerade must be left alone, calls:\n%s", calls)
	}
}

// AnnounceNAT reconciles masquerade rules for announced subnets: adds new,
// removes dropped, idempotent across ticks, and Close removes everything.
func TestAnnounceNATReconciles(t *testing.T) {
	logFile := shimBinaries(t, false)
	l, _ := captureLog(t)

	_, overlay, _ := net.ParseCIDR("10.99.0.0/16")
	_, lan1, _ := net.ParseCIDR("192.168.1.0/24")
	_, lan2, _ := net.ParseCIDR("192.168.50.0/24")

	r := &linuxRouter{iface: "wgtest0", port: 51822, added: map[string]bool{}, announceNAT: map[string]string{}, log: l}
	if err := r.AnnounceNAT(overlay, []net.IPNet{*lan1}); err != nil {
		t.Fatalf("announce nat: %v", err)
	}
	if err := r.AnnounceNAT(overlay, []net.IPNet{*lan1}); err != nil {
		t.Fatalf("idempotent re-announce: %v", err)
	}
	b, _ := os.ReadFile(logFile)
	if got := strings.Count(string(b), "-s 10.99.0.0/16 -d 192.168.1.0/24"); got != 1 {
		t.Fatalf("want exactly one masquerade rule per announcement, got %d:\n%s", got, b)
	}
	// The inserted rule MUST carry the meshd comment tag — untagged rules are
	// invisible to the stop-time sweep (a lost tag shipped once and left
	// orphaned masquerades behind).
	if !strings.Contains(string(b), "-m comment --comment routewire-meshd") {
		t.Fatalf("announce masquerade rules must be tagged for stop-cleanup:\n%s", b)
	}

	// Add a second announcement, drop the first: only the second remains.
	if err := r.AnnounceNAT(overlay, []net.IPNet{*lan2}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	b, _ = os.ReadFile(logFile)
	if !strings.Contains(string(b), "-d 192.168.50.0/24") {
		t.Fatal("second announcement must be added")
	}
	if strings.Count(string(b), "-D POSTROUTING -s 10.99.0.0/16 -d 192.168.1.0/24") != 1 {
		t.Fatalf("dropped announcement's rule must be removed:\n%s", b)
	}

	// Close removes the remainder.
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	b, _ = os.ReadFile(logFile)
	if strings.Count(string(b), "-D POSTROUTING -s 10.99.0.0/16 -d 192.168.50.0/24") != 1 {
		t.Fatalf("close must remove remaining announce rules:\n%s", b)
	}
	if len(r.announceNAT) != 0 {
		t.Fatalf("tracking must be empty after close, got %+v", r.announceNAT)
	}
}
