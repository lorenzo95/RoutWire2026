package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"routewire/internal/config"
	"routewire/internal/engine"
	"routewire/internal/mesh"
)

var defaultStunServers = []string{
	"stun.l.google.com:19402",
	"stun1.l.google.com:19402",
	"stun.cloudflare.com:3478",
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// dsnet-style subcommands: "meshd init", "meshd export", "meshd stop"
	// are sugar for their flag equivalents.
	os.Args = append(os.Args[:1], expandSubcommand(os.Args[1:])...)

	// Values of these flags are consumed via setFlags/ResolveMesh; they are
	// registered so -help documents them and flag.Visit sees which were
	// explicitly set.
	flag.String("psk", "", "mesh PSK (or MESH_PSK / config psk)")
	flag.String("name", "", "node name [a-z0-9-] (default hostname)")
	flag.String("iface", "", "wireguard interface (default wgmesh0)")
	flag.String("cidr", "", "overlay CIDR (default 10.99.0.0/16)")
	flag.Int("port", 0, "WireGuard listen port (default 51820)")
	flag.Int("mtu", 0, "interface MTU (default 1420)")
	flag.Duration("poll", 0, "reconcile interval (default 15s)")
	flag.Duration("stale", 0, "handshake staleness before re-race (default 180s)")
	flag.String("stun", "", "STUN servers, comma-separated (empty disables)")
	flag.String("proxies", "", "OpenDHT proxies, comma-separated")
	flag.String("backend", "", "roster backend: opendht | mock (default opendht)")
	flag.String("announce", "", "subnets this node serves, comma-separated CIDRs")
	flag.Bool("dry-run", false, "no kernel changes; simulate device control")

	var (
		configF = flag.String("config", "", "config file path (.yaml or .json)")

		stopF   = flag.Bool("stop", false, "delete interface and exit")
		exportF = flag.Bool("export", false, "generate a wg-quick config for -remote and exit")
		initF   = flag.Bool("init", false, "write a starter config file (-out path, default meshd.yaml) and exit")
		peekF   = flag.Bool("peek", false, "fetch the live DHT roster, verify records, print them; no interface needed")
		removeF = flag.Bool("remove", false, "delete a remote device (-remote NAME) from this hub")

		serviceF   = flag.Bool("service", false, "manage the system service (with -install / -uninstall)")
		installF   = flag.Bool("install", false, "with -service: install and start the system service")
		uninstallF = flag.Bool("uninstall", false, "with -service: stop and remove the system service")
		systemF    = flag.String("system", "", `with -service: init system: auto (default), systemd, sysvinit`)
		insecureF  = flag.Bool("dht-insecure", false, "skip TLS verification for DHT proxies (for HTTPS-intercepting networks; payloads stay end-to-end encrypted)")

		remoteF = flag.String("remote", "", "remote device name (for -export / -remove)")
		outF    = flag.String("out", "", "write exported config to file (0600) instead of stdout")
		epF     = flag.String("endpoint", "", "endpoint for exported peer (default: this node's best local address:port)")
		routesF = flag.String("routes", "all", `with -export: "all" (default) bakes every announced subnet into AllowedIPs; "none" = overlay only`)
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `routewire meshd — decentralized WireGuard mesh daemon

usage:
  meshd init [-out FILE] [flags...]        write a starter config (generates PSK if unset)
  meshd [-config FILE] [flags...]          run the node
  meshd export -remote NAME [-routes none] [-out FILE] [-endpoint host:port]
                                           generate a wg-quick config for an agent-less device
  meshd remove -remote NAME                 stop serving a remote device (drops its peer + NAT)
  meshd service -install [-system auto|systemd|sysvinit]
                                           install and start as a system service (boot-persistent)
  meshd service -uninstall                  stop and remove the system service
  meshd peek                               fetch the live DHT roster, verify records, print them
  meshd stop                               delete the interface and exit

flags:
`)
		flag.PrintDefaults()
	}
	flag.Parse()

	if len(os.Args) <= 1 {
		fmt.Fprintf(os.Stderr, `routewire meshd — decentralized WireGuard mesh daemon

no command given. quick start:

  sudo meshd init                    set up this node (writes /etc/meshd.yaml,
                                     generates the mesh PSK — keep it handy)
  sudo meshd -config /etc/meshd.yaml run it (or install a systemd unit)
  meshd peek                         see who is in the mesh right now

add another node (same PSK, different name):
  MESH_PSK=<psk> meshd init -name beta

share the network with phones and other agent-less devices:
  meshd export -remote phone-1 -routes all -out phone1.conf

run 'meshd -h' for every flag and subcommand.
`)
		os.Exit(0)
	}

	if *serviceF {
		runService(*configF, *installF, *uninstallF, *systemF)
		return
	}

	setFlags := map[string]string{}
	flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = f.Value.String() })

	env := map[string]string{}
	if v := os.Getenv("MESH_PSK"); v != "" {
		env["MESH_PSK"] = v
	}
	if v := os.Getenv("MESH_NAME"); v != "" {
		env["MESH_NAME"] = v
	}

	var fileCfg *config.MeshConfig
	if *configF != "" {
		var err error
		fileCfg, err = config.LoadMeshConfig(*configF)
		if err != nil {
			fatalf("config: %v", err)
		}
	}

	defs := &config.MeshConfig{
		Name:     defaultName(),
		IFace:    "wgmesh0",
		CIDR:     "10.99.0.0/16",
		Port:     51820,
		MTU:      1420,
		Poll:     "15s",
		Stale:    "3m",
		Backend:  "opendht",
	}
	resolved := config.ResolveMesh(defs, fileCfg, env, setFlags)

	logger := log.Default()
	cidrIP, cidrNet, err := net.ParseCIDR(resolved.CIDR)
	if err != nil || cidrIP == nil {
		fatalf("bad cidr %q: %v", resolved.CIDR, err)
	}
	poll, err := time.ParseDuration(resolved.Poll)
	if err != nil {
		fatalf("bad poll %q: %v", resolved.Poll, err)
	}
	staleAfter, err := time.ParseDuration(resolved.Stale)
	if err != nil {
		fatalf("bad stale %q: %v", resolved.Stale, err)
	}
	for _, a := range resolved.Announce {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(a)); err != nil {
			fatalf("bad announce entry %q: %v", a, err)
		}
	}

	deriver := mesh.NewDeriver(resolved.PSK)

	if *initF {
		runInit(resolved, *outF, deriver, cidrNet)
		return
	}

	store := newStore(resolved.Backend, strings.Join(resolved.Proxies, ","), *insecureF)

	spokesPath := ""
	if *configF != "" {
		spokesPath = filepath.Join(filepath.Dir(*configF), "meshd.spokes")
	}

	if *exportF {
		runExport(deriver, store, cidrNet, resolved, *remoteF, *outF, *epF, *routesF, spokesPath, logger)
		return
	}

	if *removeF {
		runRemove(spokesPath, *remoteF)
		return
	}

	if strings.TrimSpace(resolved.PSK) == "" {
		fatalf("missing PSK: run 'meshd init' first, or pass -psk / MESH_PSK / a config file")
	}

	if *peekF {
		runPeek(deriver, store, cidrNet)
		return
	}

	if *stopF {
		if err := stopInterface(resolved.IFace); err != nil {
			fatalf("stop: %v", err)
		}
		fmt.Println("stopped")
		return
	}

	var dev mesh.Device
	var stopper func()
	var router mesh.Router
	if resolved.DryRun {
		dev = mesh.NewFakeDevice()
		stopper = func() {}
		logger.Printf("mode=dry-run device=fake")
	} else {
		ld, err := mesh.NewLinuxDevice(resolved.IFace)
		if err != nil {
			fatalf("device: %v", err)
		}
		rtr, err := mesh.NewLinuxRouter(resolved.IFace, resolved.Port, logger)
		switch {
		case errors.Is(err, mesh.ErrNoIptables):
			logger.Printf("warning: %v — port/forwarding/NAT management disabled; handle on the host", err)
			rtr = nil
		case err != nil:
			ld.Close()
			fatalf("router: %v", err)
		}
		router = rtr
		dev = ld
		stopper = func() {
			_ = ld.Close()
			if err := rtr.Close(); err != nil {
				logger.Printf("router cleanup: %v", err)
			}
			if err := ld.Delete(); err != nil { // tear down iface + peers on exit
				logger.Printf("cleanup: %v", err)
			}
		}
	}

	daemon, err := mesh.NewDaemon(mesh.Config{
		Name:        resolved.Name,
		IFace:       resolved.IFace,
		CIDR:        cidrNet,
		Port:        resolved.Port,
		MTU:         resolved.MTU,
		Poll:        poll,
		StaleAfter:  staleAfter,
		StunServers: resolved.Stun,
		Announce:    resolved.Announce,
		Router:      router,
		SpokesFile:  spokesPath,
	}, deriver, store, dev, logger)
	if err != nil {
		fatalf("daemon: %v", err)
	}

	pubKey, err := deriver.NodeWGPubKey(daemon.Name())
	if err != nil {
		fatalf("key: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Printf("routewire/meshd starting node=%s overlay=%s listen=%d iface=%s backend=%s announce=%v roster=%s",
		daemon.Name(), daemon.OverlayAddr().IP, resolved.Port, resolved.IFace, resolved.Backend,
		resolved.Announce, deriver.RosterKey())
	logger.Printf("public-key=%s", pubKey)

	if err := daemon.Setup(); err != nil {
		fatalf("setup: %v%s", err, setupHint(err))
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		daemon.Run(ctx)
	}()

	firstTickCtx, cancelFirst := context.WithTimeout(context.Background(), 30*time.Second)
	if err := daemon.Tick(firstTickCtx); err != nil {
		logger.Printf("first tick: %v", err)
	}
	cancelFirst()

	<-done
	stopper()
	logger.Printf("bye")
}

func runPeek(deriver *mesh.Deriver, store *engine.ReliableStore, cidr *net.IPNet) {
	ro, err := mesh.NewRoster(deriver, "", store, cidr)
	if err != nil {
		fatalf("roster: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	recs, err := ro.FetchStable(ctx, 4, time.Second)
	if err != nil {
		fatalf("fetch: %v", err)
	}
	names := mesh.Names(recs)
	fmt.Printf("roster %s — %d live node(s) (signature- and binding-verified)\n",
		deriver.RosterKey(), len(names))
	if len(names) == 0 {
		return
	}
	fmt.Printf("%-14s %-16s %5s  %5s  %-46s %s\n", "NAME", "OVERLAY", "PORT", "AGE", "CANDIDATES", "ANNOUNCED")
	now := time.Now()
	for _, n := range names {
		r := recs[n]
		cands := make([]string, 0, len(r.Candidates))
		for _, c := range r.Candidates {
			cands = append(cands, fmt.Sprintf("%s:%s", c.Type, c.Addr))
		}
		candStr := strings.Join(cands, "|")
		if candStr == "" {
			candStr = "-"
		}
		advStr := strings.Join(r.Adv, ",")
		if advStr == "" {
			advStr = "-"
		}
		fmt.Printf("%-14s %-16s %5d  %4ds  %-46s %s\n",
			n, r.IP, r.Port, now.Unix()-r.TS, candStr, advStr)
	}
}

func runRemove(spokesPath, remoteRaw string) {
	name := mesh.NormalizeName(remoteRaw)
	if name == "" {
		fatalf("-remove requires -remote NAME")
	}
	if spokesPath == "" {
		fatalf("no config file found; pass -config /path/meshd.yaml so meshd can locate the spoke list")
	}
	if err := mesh.RemoveSpoke(spokesPath, name); err != nil {
		fatalf("remove spoke %q: %v", name, err)
	}
	fmt.Printf("removed spoke %q (this hub will drop its peer + NAT on the next tick)\n", name)
}

func runExport(deriver *mesh.Deriver, store *engine.ReliableStore, cidr *net.IPNet, rc *config.MeshConfig, remoteRaw, outPath, endpointFlag, routesFlag, spokesPath string, logger *log.Logger) {
	if strings.TrimSpace(rc.PSK) == "" {
		fatalf("missing PSK: run 'meshd init' first, or pass -psk / MESH_PSK / a config file")
	}
	if remoteRaw == "" {
		fatalf("-export requires -remote NAME")
	}
	switch routesFlag {
	case "", "all", "none":
	default:
		fatalf(`-routes must be "all" or "none"`)
	}
	bakeRoutes := routesFlag != "none"

	endpoint := endpointFlag
	if endpoint == "" {
		cands := mesh.LocalCandidates(rc.Port)
		for _, c := range cands {
			if c.Type == mesh.CandHost {
				endpoint = c.Addr
				break
			}
		}
		if endpoint == "" {
			for _, c := range cands {
				if c.Type == mesh.CandSRFLX {
					endpoint = c.Addr
					break
				}
			}
		}
		if endpoint == "" {
			fatalf("no usable local address found; pass -endpoint host:port explicitly")
		}
		logger.Printf("endpoint auto-detected: %s (override with -endpoint)", endpoint)
	}

	extra := []string(nil)
	if bakeRoutes {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ro, err := mesh.NewRoster(deriver, rc.Name, store, cidr)
		if err != nil {
			fatalf("roster: %v", err)
		}
		recs, err := ro.FetchStable(ctx, 4, time.Second)
		if err != nil {
			logger.Printf("warning: could not fetch roster (%v); exporting overlay-only routes", err)
		}
		if len(rc.Announce) == 0 && len(recs) > 0 {
			logger.Printf("note: -announce not set; this node's own announced subnets (if any) are not baked into the exported routes")
		}
		for _, ipnet := range mesh.ParseCIDRs(rc.Announce) { // our own announcements route via the hub too
			extra = append(extra, ipnet.String())
		}
		for _, rec := range recs {
			extra = append(extra, rec.Adv...)
			logger.Printf("roster: %s announced %v", rec.Name, rec.Adv)
		}
	}

	conf, err := mesh.ExportConf(mesh.ExportConfInput{
		Deriver:     deriver,
		CIDR:        cidr,
		LocalName:   rc.Name,
		RemoteName:  remoteRaw,
		Endpoint:    endpoint,
		ExtraRoutes: extra,
		MTU:         rc.MTU,
	})
	if err != nil {
		fatalf("export: %v", err)
	}

	if err := mesh.AddSpoke(spokesPath, remoteRaw); err != nil {
		logger.Printf("WARNING: could not persist spoke %q (%v); it will not survive a hub restart", mesh.NormalizeName(remoteRaw), err)
	} else if spokesPath != "" {
		logger.Printf("registered spoke %q (hub peers + NATs it; nothing published to the DHT)", mesh.NormalizeName(remoteRaw))
	}

	if outPath == "" {
		os.Stdout.Write(conf)
		return
	}
	if err := os.WriteFile(outPath, conf, 0o600); err != nil {
		fatalf("write %s: %v", outPath, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (mode 0600)\n", outPath)
}

// subcommandFlags maps a leading subcommand to its flag equivalent so
// "meshd init -name x" parses identically to "meshd -init -name x".
var subcommandFlags = map[string]string{
	"init":    "-init",
	"export":  "-export",
	"stop":    "-stop",
	"peek":    "-peek",
	"remove":  "-remove",
	"service": "-service",
}

// valueFlags are flags that consume a value in the "-flag value" form; used to
// avoid mistaking a node literally named "peek"/"init"/etc. for a subcommand.
var valueFlags = map[string]bool{
	"psk": true, "name": true, "iface": true, "cidr": true, "port": true,
	"mtu": true, "poll": true, "stale": true, "stun": true, "proxies": true,
	"backend": true, "announce": true, "config": true, "remote": true,
	"out": true, "endpoint": true, "routes": true, "system": true,
}

// expandSubcommand maps a subcommand to its flag equivalent wherever it
// appears in the argument list (so "meshd -config file.yaml peek" works the
// same as "meshd peek -config file.yaml"), moving it to the front so the flag
// package parses everything after it normally.
func expandSubcommand(args []string) []string {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		// A bare token right after a value-taking flag is that flag's value,
		// not a subcommand (e.g. "meshd -name peek").
		if i > 0 {
			prev := args[i-1]
			if strings.HasPrefix(prev, "-") && !strings.Contains(prev, "=") &&
				valueFlags[strings.TrimLeft(prev, "-")] {
				continue
			}
		}
		if flagName, ok := subcommandFlags[a]; ok {
			rest := append(append([]string{}, args[:i]...), args[i+1:]...)
			return append([]string{flagName}, rest...)
		}
	}
	return args
}

func runInit(rc *config.MeshConfig, outPath string, d *mesh.Deriver, cidr *net.IPNet) {
	path := outPath
	if path == "" {
		if os.Geteuid() == 0 {
			path = "/etc/meshd.yaml"
		} else {
			path = "meshd.yaml"
		}
	}
	if _, err := os.Stat(path); err == nil {
		fatalf("refusing to overwrite existing %s (move it aside or pass -out)", path)
	}
	generated := false
	if strings.TrimSpace(rc.PSK) == "" {
		rc.PSK = genPSK()
		generated = true
	}
	if err := os.WriteFile(path, renderConfigYAML(rc), 0o600); err != nil {
		fatalf("write %s: %v", path, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (mode 0600)\n", path)
	if generated {
		fmt.Fprintf(os.Stderr, "generated new PSK:\n  %s\n", rc.PSK)
		fmt.Fprint(os.Stderr, "share this exact value with every node you want in the mesh\n")
	} else {
		fmt.Fprint(os.Stderr, "note: your PSK is inside this file — keep it private\n")
	}

	// dsnet-style report: show the identity this node will have, derived
	// from PSK+name before anything touches the network.
	pubKey, err := d.NodeWGKey(rc.Name)
	if err != nil {
		fatalf("key: %v", err)
	}
	ip, err := d.OverlayIP(rc.Name, cidr)
	if err != nil {
		fatalf("overlay ip: %v", err)
	}
	pskStatus := "provided (stored in file)"
	if generated {
		pskStatus = "generated new secret (stored in file)"
	}
	fmt.Fprintf(os.Stderr, `
node:       %s
config:     %s
address:    %s
public key: %s
listen:     %d/udp on %s
backend:    %s
roster key: %s
psk:        %s

other nodes: repeat init with the SAME psk and a DIFFERENT name:
  MESH_PSK=<psk> meshd init -name beta
start this node:
  meshd -config %s
`, rc.Name, path, ip, pubKey.PublicKey().String(), rc.Port, rc.IFace,
		rc.Backend, d.RosterKey(), pskStatus, path)
}

// genPSK returns a fresh 256-bit random secret, base64-encoded.
func genPSK() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		fatalf("generate psk: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func renderConfigYAML(rc *config.MeshConfig) []byte {
	var b strings.Builder
	writeList := func(title, comment string, items []string) {
		fmt.Fprintf(&b, "\n# %s\n%s:", comment, title)
		if len(items) == 0 {
			b.WriteString(" []")
		}
		b.WriteByte('\n')
		for _, it := range items {
			fmt.Fprintf(&b, "  - %s\n", strconv.Quote(it))
		}
	}

	stun := rc.Stun
	if len(stun) == 0 {
		stun = defaultStunServers
	}
	proxies := rc.Proxies
	if len(proxies) == 0 {
		proxies = config.DefaultProxies
	}

	b.WriteString("# routewire/meshd node configuration\n")
	b.WriteString("# layers: built-in defaults < this file < env (MESH_PSK, MESH_NAME) < explicit flags\n")
	b.WriteString("\n# shared mesh secret: every node of a mesh uses the same value\n")
	fmt.Fprintf(&b, "psk: %s\n", strconv.Quote(rc.PSK))
	fmt.Fprintf(&b, "\n# node identity [a-z0-9-] (default: hostname)\nname: %s\n", strconv.Quote(rc.Name))
	fmt.Fprintf(&b, "# kernel wireguard interface created and managed by meshd\niface: %s\n", strconv.Quote(rc.IFace))
	fmt.Fprintf(&b, "# overlay network from which every node IP derives\ncidr: %s\n", rc.CIDR)
	fmt.Fprintf(&b, "port: %d # wireguard UDP listen port\nmtu: %d\n", rc.Port, rc.MTU)

	fmt.Fprintf(&b, "\n# reconcile cadence / endpoint re-race threshold\npoll: %s\nstale: %s\n", rc.Poll, rc.Stale)

	writeList("stun", "STUN servers for NAT discovery (set to [] to disable)", stun)
	writeList("proxies", "OpenDHT roster proxies", proxies)

	fmt.Fprintf(&b, "\n# roster backend: opendht | mock\nbackend: %s\n", rc.Backend)
	writeList("announce", "extra subnets THIS node serves to the mesh", rc.Announce)

	fmt.Fprintf(&b, "\n# simulate device control without touching the kernel\ndry_run: %t\n", rc.DryRun)
	return []byte(b.String())
}

func newStore(backend, proxyOverride string, insecureTLS bool) *engine.ReliableStore {
	switch backend {
	case "mock":
		return engine.NewReliable(engine.NewMockStore(10*time.Minute, time.Now))
	case "opendht":
		endpoints := config.DefaultProxies
		if proxyOverride != "" {
			endpoints = nil
			for _, e := range strings.Split(proxyOverride, ",") {
				if e = strings.TrimSpace(e); e != "" {
					endpoints = append(endpoints, e)
				}
			}
		}
		return engine.NewReliable(engine.NewOpenDHT(endpoints, engine.WithInsecureTLS(insecureTLS)))
	default:
		fatalf("unknown backend %q (opendht|mock)", backend)
		return nil
	}
}

// setupHint turns common interface-creation failures into actionable advice.
func setupHint(err error) string {
	var hint string
	switch {
	case errors.Is(err, syscall.EOPNOTSUPP), strings.Contains(strings.ToLower(err.Error()), "not supported"):
		hint = "\n  the kernel has no WireGuard support: needs Linux >= 5.6, or the\n" +
			"  wireguard module/dkms package for this kernel (try: modprobe wireguard)"
	case errors.Is(err, syscall.EPERM):
		hint = "\n  missing privileges: run as root, or in containers add --cap-add=NET_ADMIN"
	case errors.Is(err, syscall.EEXIST):
		hint = "\n  leftover interface: sudo meshd stop (or: ip link del <iface>)"
	}
	return hint
}

func stopInterface(iface string) error {
	if iface == "" {
		return errors.New("no iface")
	}
	ld, err := mesh.NewLinuxDevice(iface)
	if err != nil {
		return err
	}
	defer ld.Close()
	return ld.Delete()
}

func defaultName() string {
	h, err := os.Hostname()
	if err != nil {
		return "node-" + strconv.Itoa(os.Getpid())
	}
	n := strings.ToLower(h)
	n = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		default:
			return -1
		}
	}, n)
	if n == "" {
		n = "node"
	}
	return n
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
