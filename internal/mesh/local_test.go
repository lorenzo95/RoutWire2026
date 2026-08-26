package mesh

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	stun "github.com/pion/stun/v3"
)

func TestIPCandidatesFilters(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("169.254.9.9"),
		net.ParseIP("192.168.1.50"),
		net.ParseIP("10.0.0.7"),
		net.ParseIP("0.0.0.0"),
		net.ParseIP("2001:db8::1"),
		net.ParseIP("fe80::1"),
	}
	got := ipCandidates(ips, 51820)
	addrs := map[string]bool{}
	for _, c := range got {
		if c.Type != CandHost {
			t.Fatalf("expected host candidate, got %s", c.Type)
		}
		addrs[c.Addr] = true
	}
	for _, want := range []string{"192.168.1.50:51820", "10.0.0.7:51820", "[2001:db8::1]:51820"} {
		if !addrs[want] {
			t.Fatalf("missing %s in %v", want, addrs)
		}
	}
	for _, bad := range []string{"127.0.0.1", "169.254.9.9", "0.0.0.0", "fe80::1"} {
		for a := range addrs {
			if len(a) >= len(bad) && a[:len(bad)] == bad && (len(a) == len(bad) || a[len(bad)] == ':') {
				t.Fatalf("leaked %s as %s", bad, a)
			}
		}
	}
}

func TestAnnounceIfaceRules(t *testing.T) {
	cases := []struct {
		name  string
		flags net.Flags
		want  bool
	}{
		{"eth0", net.FlagUp, true},
		{"ens18", net.FlagUp, true},
		{"lo", net.FlagLoopback | net.FlagUp, false},
		{"wg0", net.FlagUp | net.FlagPointToPoint, false},
		{"docker0", net.FlagUp, false},
		{"br-abc123", net.FlagUp, false},
		{"veth9f3a21", net.FlagUp, false},
		{"tun0", net.FlagUp | net.FlagPointToPoint, false},
		{"ZT-If", net.FlagUp, false},
	}
	for _, c := range cases {
		if got := announceIface(net.Interface{Name: c.name, Flags: c.flags}); got != c.want {
			t.Fatalf("announceIface(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestGatherSRFLXAgainstFakeServer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	serverAddr := pc.LocalAddr().String()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := stun.New()
			req.Raw = append(req.Raw[:0], buf[:n]...)
			if req.Decode() != nil {
				continue
			}
			srcAddr := src.(*net.UDPAddr)
			resp := stun.MustBuild(stun.NewTransactionIDSetter(req.TransactionID))
			resp.Type = stun.NewType(stun.MethodBinding, stun.ClassSuccessResponse)
			xor := stun.XORMappedAddress{IP: srcAddr.IP, Port: srcAddr.Port}
			if xor.AddTo(resp) != nil {
				continue
			}
			pc.WriteTo(resp.Raw, src)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := GatherSRFLX(ctx, []string{serverAddr}, time.Second)
	if len(got) != 1 || got[0].Type != CandSRFLX {
		t.Fatalf("want one srflx candidate, got %+v", got)
	}
	host, port, err := net.SplitHostPort(got[0].Addr)
	if err != nil || host != "127.0.0.1" {
		t.Fatalf("mapped ip should be the loopback source, got %q (%v)", got[0].Addr, err)
	}
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatalf("bad port %q", port)
	}
}

func TestGatherSRFLXToleratesDeadServers(t *testing.T) {
	dead, _ := net.ListenPacket("udp", "127.0.0.1:0")
	deadAddr := dead.LocalAddr().String()
	dead.Close()

	livePC, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer livePC.Close()
	go serveStunEcho(livePC)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got := GatherSRFLX(ctx, []string{deadAddr, livePC.LocalAddr().String()}, 300*time.Millisecond)
	if len(got) != 1 {
		t.Fatalf("dead server must be skipped, got %+v", got)
	}
}

func serveStunEcho(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		req := stun.New()
		req.Raw = append(req.Raw[:0], buf[:n]...)
		if req.Decode() != nil {
			continue
		}
		srcAddr := src.(*net.UDPAddr)
		resp := stun.MustBuild(stun.NewTransactionIDSetter(req.TransactionID))
		resp.Type = stun.NewType(stun.MethodBinding, stun.ClassSuccessResponse)
		if (&stun.XORMappedAddress{IP: srcAddr.IP, Port: srcAddr.Port}).AddTo(resp) != nil {
			continue
		}
		pc.WriteTo(resp.Raw, src)
	}
}
