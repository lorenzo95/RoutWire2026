package mesh

import (
	"net"
	"sort"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// FakeDevice is an in-memory Device for tests and -dry-run. Applying an
// endpoint never produces a handshake by itself: handshakes appear only when
// Traffic() is called for a peer whose last applied endpoint is Reachable,
// mirroring how a real kernel interface behaves under probe traffic.
type FakeDevice struct {
	mu        sync.Mutex
	setupKey  wgtypes.Key
	SetupCnt  int
	History   [][]PeerDesire
	Routes    []net.IPNet
	Reachable func(ep *net.UDPAddr) bool
	hs        map[wgtypes.Key]time.Time
	lastEP    map[wgtypes.Key]*net.UDPAddr
	// observed, when set, is the endpoint Endpoint() reports — simulating the
	// roamed/peer-reflexive address WireGuard tracks from inbound traffic.
	observed map[wgtypes.Key]*net.UDPAddr
}

func NewFakeDevice() *FakeDevice {
	return &FakeDevice{
		hs:       make(map[wgtypes.Key]time.Time),
		lastEP:   make(map[wgtypes.Key]*net.UDPAddr),
		observed: make(map[wgtypes.Key]*net.UDPAddr),
	}
}

func (f *FakeDevice) Setup(key wgtypes.Key, _, _ int, _, _ *net.IPNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setupKey = key
	f.SetupCnt++
	return nil
}

func (f *FakeDevice) Apply(peers []PeerDesire) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := append([]PeerDesire(nil), peers...)
	sort.Slice(cp, func(i, j int) bool { return cp[i].Name < cp[j].Name })
	f.History = append(f.History, cp)
	for _, p := range peers {
		if p.Endpoint != nil {
			f.lastEP[p.Pub] = p.Endpoint
		}
	}
	return nil
}

func (f *FakeDevice) ApplyRoutes(routes []net.IPNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Routes = routes
	return nil
}

// Traffic simulates probe traffic reaching a peer through the tunnel.
func (f *FakeDevice) Traffic(pub wgtypes.Key) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ep := f.lastEP[pub]
	if ep == nil {
		return
	}
	if f.Reachable != nil && !f.Reachable(ep) {
		return
	}
	f.hs[pub] = time.Now()
}

func (f *FakeDevice) Handshake(pub wgtypes.Key) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hs[pub]
}

func (f *FakeDevice) Endpoint(pub wgtypes.Key) *net.UDPAddr {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ep, ok := f.observed[pub]; ok && ep != nil {
		return ep
	}
	return f.lastEP[pub]
}

// SetObserved simulates WireGuard roaming a peer to a new observed address
// from its own inbound traffic.
func (f *FakeDevice) SetObserved(pub wgtypes.Key, ep *net.UDPAddr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.observed[pub] = ep
}

// SetHandshake forces a handshake timestamp (e.g. an aged one to simulate
// staleness).
func (f *FakeDevice) SetHandshake(pub wgtypes.Key, t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hs[pub] = t
}

func (f *FakeDevice) Applies() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.History)
}
