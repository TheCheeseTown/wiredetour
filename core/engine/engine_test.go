package engine

import (
	"errors"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun"
)

// fakeTUN plays the OS side of the tun device.
type fakeTUN struct {
	fromOS chan []byte // packets the OS sends into the tunnel
	toOS   chan []byte // packets delivered to the OS
	events chan tun.Event
	closed chan struct{}
	once   sync.Once
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{
		fromOS: make(chan []byte, 16),
		toOS:   make(chan []byte, 16),
		events: make(chan tun.Event),
		closed: make(chan struct{}),
	}
}

func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p := <-f.fromOS:
		sizes[0] = copy(bufs[0][offset:], p)
		return 1, nil
	case <-f.closed:
		return 0, os.ErrClosed
	}
}

func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		f.toOS <- append([]byte(nil), b[offset:]...)
	}
	return len(bufs), nil
}

func (f *fakeTUN) File() *os.File           { return nil }
func (f *fakeTUN) MTU() (int, error)        { return 1420, nil }
func (f *fakeTUN) Name() (string, error)    { return "utun-test", nil }
func (f *fakeTUN) Events() <-chan tun.Event { return f.events }
func (f *fakeTUN) BatchSize() int           { return 1 }
func (f *fakeTUN) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

var (
	dnsServer = netip.MustParseAddr("10.8.0.1")
	ifaceAddr = netip.MustParseAddr("10.8.0.2")
	osClient  = netip.AddrPortFrom(ifaceAddr, 5353)
)

// harness wires an engine to a fake OS and a fake peer whose DNS server
// answers every A query with answerIP.
type harness struct {
	t       *testing.T
	eng     *Engine
	os      *fakeTUN
	dev     tun.Device
	applied chan []netip.Prefix

	mu         sync.Mutex
	upstreamN  int
	dropDNS    bool
	answerIP   netip.Addr
	applyErr   error
	appliedSet []netip.Prefix
	peerSeen   []netip.Addr // destinations of non-DNS packets wireguard received
}

func newHarness(t *testing.T, cfg Config) *harness {
	t.Helper()
	h := &harness{
		t:        t,
		os:       newFakeTUN(),
		applied:  make(chan []netip.Prefix, 16),
		answerIP: netip.MustParseAddr("93.184.216.34"),
	}
	h.eng = New(cfg, func(set []netip.Prefix) error {
		h.mu.Lock()
		err := h.applyErr
		if err == nil {
			h.appliedSet = set
		}
		h.mu.Unlock()
		h.applied <- set
		return err
	}, t.Logf)
	h.dev = h.eng.Wrap(h.os)
	go h.peer()
	t.Cleanup(func() { h.dev.Close() })
	return h
}

// peer plays wireguard-go: it reads from the wrapped device and answers
// upstream DNS queries by writing replies back into it.
func (h *harness) peer() {
	bufs := [][]byte{make([]byte, 2048)}
	sizes := []int{0}
	for {
		n, err := h.dev.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		for i := 0; i < n; i++ {
			pkt := bufs[i][:sizes[i]]
			p, ok := parseIP(pkt)
			if !ok {
				continue
			}
			sport, dport, payload, ok := parseUDP(p.l4)
			if !ok || p.dst != dnsServer || dport != 53 {
				h.mu.Lock()
				h.peerSeen = append(h.peerSeen, p.dst)
				h.mu.Unlock()
				continue
			}
			h.mu.Lock()
			h.upstreamN++
			drop, ip := h.dropDNS, h.answerIP
			h.mu.Unlock()
			if drop {
				continue
			}
			resp := answer(h.t, payload, ip)
			out := buildUDP(netip.AddrPortFrom(dnsServer, 53), netip.AddrPortFrom(p.src, sport), resp)
			buf := make([]byte, 16+len(out))
			copy(buf[16:], out)
			h.dev.Write([][]byte{buf}, 16)
		}
	}
}

// answer builds a response with one A record for A queries, nothing otherwise.
func answer(t *testing.T, query []byte, ip netip.Addr) []byte {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		t.Fatal(err)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true, RecursionAvailable: true})
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	if q.Type == dnsmessage.TypeA {
		b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 300}, dnsmessage.AResource{A: ip.As4()})
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// query sends a DNS query from the OS and returns the parsed response.
func (h *harness) query(name string, qt dnsmessage.Type) (dnsmessage.Header, []netip.Addr) {
	h.t.Helper()
	q, err := buildQuery(name, qt)
	if err != nil {
		h.t.Fatal(err)
	}
	h.os.fromOS <- buildUDP(osClient, netip.AddrPortFrom(dnsServer, 53), q)
	select {
	case pkt := <-h.os.toOS:
		p, ok := parseIP(pkt)
		if !ok {
			h.t.Fatal("bad packet to OS")
		}
		sport, dport, payload, ok := parseUDP(p.l4)
		if !ok || sport != 53 || dport != osClient.Port() || p.src != dnsServer {
			h.t.Fatalf("unexpected reply addressing %v:%d -> %d", p.src, sport, dport)
		}
		var mp dnsmessage.Parser
		hdr, err := mp.Start(payload)
		if err != nil {
			h.t.Fatal(err)
		}
		ips, _ := answerIPs(payload)
		return hdr, ips
	case <-time.After(10 * time.Second):
		h.t.Fatal("no DNS reply to OS")
	}
	return dnsmessage.Header{}, nil
}

func baseConfig() Config {
	return Config{
		DNSServers:     []netip.Addr{dnsServer},
		Domains:        []string{"Example.com."},
		StaticRoutes:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:     []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		InterfaceAddrs: []netip.Addr{ifaceAddr},
		DynamicRoutes:  true,
	}
}

func TestMatchedDomainAddsRouteBeforeAnswer(t *testing.T) {
	h := newHarness(t, baseConfig())
	hdr, ips := h.query("www.example.com", dnsmessage.TypeA)
	if hdr.RCode != dnsmessage.RCodeSuccess || len(ips) != 1 || ips[0] != h.answerIP {
		t.Fatalf("got rcode %v ips %v", hdr.RCode, ips)
	}
	// The apply must already have happened by the time the answer arrived.
	select {
	case set := <-h.applied:
		if len(set) != 1 || set[0] != netip.MustParsePrefix("93.184.216.0/24") {
			t.Fatalf("applied %v", set)
		}
	default:
		t.Fatal("answer released before routes were applied")
	}
	if !h.eng.router.routedViaTunnel(h.answerIP) {
		t.Fatal("address not routed after answer")
	}

	// A second lookup in the same /24 needs no new apply.
	h.query("example.com", dnsmessage.TypeA)
	select {
	case set := <-h.applied:
		t.Fatalf("unexpected second apply %v", set)
	default:
	}
}

func TestStaticNetworkNeedsNoRoute(t *testing.T) {
	h := newHarness(t, baseConfig())
	h.mu.Lock()
	h.answerIP = netip.MustParseAddr("10.0.0.5")
	h.mu.Unlock()
	h.query("nas.example.com", dnsmessage.TypeA)
	select {
	case set := <-h.applied:
		t.Fatalf("static address triggered apply %v", set)
	default:
	}
}

func TestUnmatchedDomainForwardedWithoutRoute(t *testing.T) {
	h := newHarness(t, baseConfig())
	hdr, ips := h.query("other.org", dnsmessage.TypeA)
	if hdr.RCode != dnsmessage.RCodeSuccess || len(ips) != 1 {
		t.Fatalf("got %v %v", hdr.RCode, ips)
	}
	if len(h.applied) != 0 {
		t.Fatal("unmatched domain added a route")
	}
}

func TestCanaryIsNXDOMAIN(t *testing.T) {
	h := newHarness(t, baseConfig())
	hdr, _ := h.query(CanaryDomain, dnsmessage.TypeA)
	if hdr.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("canary rcode %v", hdr.RCode)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.upstreamN != 0 {
		t.Fatal("canary went upstream")
	}
}

func TestAAAAHiddenWithoutIPv6(t *testing.T) {
	h := newHarness(t, baseConfig())
	hdr, ips := h.query("www.example.com", dnsmessage.TypeAAAA)
	if hdr.RCode != dnsmessage.RCodeSuccess || len(ips) != 0 {
		t.Fatalf("got %v %v", hdr.RCode, ips)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.upstreamN != 0 {
		t.Fatal("AAAA went upstream although tunnel has no IPv6")
	}
}

func TestUpstreamTimeoutFailsClosed(t *testing.T) {
	old := upstreamTimeout
	upstreamTimeout = 50 * time.Millisecond
	t.Cleanup(func() { upstreamTimeout = old })

	h := newHarness(t, baseConfig())
	h.mu.Lock()
	h.dropDNS = true
	h.mu.Unlock()
	hdr, _ := h.query("www.example.com", dnsmessage.TypeA)
	if hdr.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode %v, want SERVFAIL", hdr.RCode)
	}
	st := h.eng.Status()
	if len(st.Failures) != 1 || st.Failures[0].Domain != "www.example.com" {
		t.Fatalf("failures %+v", st.Failures)
	}
}

func TestApplyErrorFailsClosed(t *testing.T) {
	h := newHarness(t, baseConfig())
	h.mu.Lock()
	h.applyErr = errors.New("boom")
	h.mu.Unlock()
	hdr, _ := h.query("www.example.com", dnsmessage.TypeA)
	if hdr.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode %v, want SERVFAIL", hdr.RCode)
	}
	if h.eng.router.routedViaTunnel(h.answerIP) {
		t.Fatal("failed route kept")
	}
}

func TestStaticModeWarnsOutsideNetworks(t *testing.T) {
	cfg := baseConfig()
	cfg.DynamicRoutes = false
	h := newHarness(t, cfg)
	h.query("www.example.com", dnsmessage.TypeA)
	if len(h.applied) != 0 {
		t.Fatal("static mode applied routes")
	}
	st := h.eng.Status()
	if len(st.Domains) != 1 || len(st.Domains[0].Warnings) == 0 {
		t.Fatalf("expected warning, got %+v", st.Domains)
	}
}

func TestAllowedIPsWarning(t *testing.T) {
	cfg := baseConfig()
	cfg.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	h := newHarness(t, cfg)
	h.query("www.example.com", dnsmessage.TypeA)
	st := h.eng.Status()
	if len(st.Domains) != 1 || len(st.Domains[0].Warnings) != 1 {
		t.Fatalf("expected AllowedIPs warning, got %+v", st.Domains)
	}
}

func TestTestDomain(t *testing.T) {
	h := newHarness(t, baseConfig())
	res := h.eng.TestDomain("www.example.com")
	if !res.Matched || len(res.IPs) != 1 || !res.IPs[0].ViaTunnel || res.IPs[0].LastUsedSecAgo != -1 {
		t.Fatalf("got %+v", res)
	}
	// Traffic from the OS to the address marks it used.
	h.os.fromOS <- buildUDP(netip.AddrPortFrom(ifaceAddr, 40000), netip.AddrPortFrom(h.answerIP, 443), []byte("x"))
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := h.eng.router.lastUsed(h.answerIP); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("usage not tracked")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNonDNSTrafficPassesThrough(t *testing.T) {
	h := newHarness(t, baseConfig())
	target := netip.MustParseAddr("10.0.0.9")
	h.os.fromOS <- buildUDP(netip.AddrPortFrom(ifaceAddr, 40000), netip.AddrPortFrom(target, 9999), []byte("hi"))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		seen := len(h.peerSeen) > 0 && h.peerSeen[0] == target
		h.mu.Unlock()
		if seen {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("packet not passed to wireguard")
}
