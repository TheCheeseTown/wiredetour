// Package engine implements wireDetour's split-DNS routing engine: it sits
// between the OS tun device and wireguard-go, answers DNS queries for matched
// domains through the tunnel, and adds routes for the resolved addresses
// before releasing the answer (D4).
package engine

import (
	"errors"
	"math/rand/v2"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CanaryDomain makes Firefox disable its built-in DNS-over-HTTPS when it gets
// NXDOMAIN from the system resolver (D7).
const CanaryDomain = "use-application-dns.net"

const (
	upstreamTries   = 2
	maxDomainStatus = 256
	maxFailures     = 20
)

// upstreamTimeout is per try; a var so tests can shorten it.
var upstreamTimeout = 2 * time.Second

// Config is the engine configuration, sent as JSON from Swift.
type Config struct {
	// DNSServers are the .conf `DNS =` addresses. OS queries to these on UDP
	// port 53 are intercepted; upstream queries go to them through the tunnel (D6).
	DNSServers []netip.Addr `json:"dnsServers"`
	// Domains are suffix-matched rule domains (D5).
	Domains []string `json:"domains"`
	// StaticRoutes are the Networks list (D15); they never need dynamic routes.
	StaticRoutes []netip.Prefix `json:"staticRoutes"`
	// AllowedIPs is the union of the peers' AllowedIPs, used only for warnings (D10).
	AllowedIPs []netip.Prefix `json:"allowedIPs"`
	// InterfaceAddrs are the tunnel's own addresses, used as the source of
	// upstream queries and to decide IPv6 handling (D8).
	InterfaceAddrs []netip.Addr `json:"interfaceAddrs"`
	// DynamicRoutes enables the dynamic engine (M3). When false, matched
	// domains are only resolved through the tunnel; no routes are added.
	DynamicRoutes bool `json:"dynamicRoutes"`
}

// Logger receives engine log lines. Never pass domain names to it (D19).
type Logger func(format string, args ...any)

type Engine struct {
	cfg    Config
	hasV6  bool
	src4   netip.Addr
	src6   netip.Addr
	router *router
	logf   Logger

	inject chan []byte                  // packets to hand to wireguard as if they came from the OS
	writer atomic.Pointer[func([]byte)] // writes a packet to the OS; set by Wrap

	mu       sync.Mutex
	pending  map[uint16]chan []byte // upstream source port → reply
	domains  map[string]*DomainStatus
	failures []Failure

	closeOnce sync.Once
	closed    chan struct{}
}

func New(cfg Config, apply ApplyFunc, logf Logger) *Engine {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	e := &Engine{
		cfg:     cfg,
		logf:    logf,
		inject:  make(chan []byte, 64),
		pending: map[uint16]chan []byte{},
		domains: map[string]*DomainStatus{},
		closed:  make(chan struct{}),
	}
	for i, d := range e.cfg.Domains {
		e.cfg.Domains[i] = normalizeName(d)
	}
	for _, a := range cfg.InterfaceAddrs {
		a = a.Unmap()
		if a.Is4() && !e.src4.IsValid() {
			e.src4 = a
		}
		if a.Is6() && !e.src6.IsValid() {
			e.src6 = a
			e.hasV6 = true
		}
	}
	e.router = newRouter(cfg.StaticRoutes, apply)
	return e
}

func (e *Engine) Close() {
	e.closeOnce.Do(func() {
		close(e.closed)
		e.router.close()
	})
}

func normalizeName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func suffixMatch(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// matches reports whether name falls under one of the rule domains (D5).
func (e *Engine) matches(name string) bool {
	for _, d := range e.cfg.Domains {
		if suffixMatch(name, d) {
			return true
		}
	}
	return false
}

func (e *Engine) isDNSServer(a netip.Addr) bool {
	a = a.Unmap()
	for _, s := range e.cfg.DNSServers {
		if s.Unmap() == a {
			return true
		}
	}
	return false
}

func (e *Engine) inAllowedIPs(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range e.cfg.AllowedIPs {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// handleOutbound inspects a packet going from the OS towards the tunnel.
// It returns true if the engine consumed the packet.
func (e *Engine) handleOutbound(pkt []byte) bool {
	dst, ok := dstAddr(pkt)
	if !ok {
		return false
	}
	if !e.isDNSServer(dst) {
		e.router.touch(dst)
		return false
	}
	p, ok := parseIP(pkt)
	if !ok {
		return false
	}
	switch p.proto {
	case protoUDP:
		sport, dport, payload, ok := parseUDP(p.l4)
		if !ok || dport != 53 {
			return false
		}
		query := append([]byte(nil), payload...)
		client := netip.AddrPortFrom(p.src, sport)
		server := netip.AddrPortFrom(p.dst, 53)
		go func() {
			resp := e.Resolve(query)
			if resp != nil {
				e.deliverToOS(buildUDP(server, client, resp))
			}
		}()
		return true
	case protoTCP:
		// DNS over TCP would bypass the route hold, so drop it (fail closed, D20).
		// We never set the TC bit, so clients have no reason to retry over TCP.
		if len(p.l4) >= 4 && uint16(p.l4[2])<<8|uint16(p.l4[3]) == 53 {
			return true
		}
	}
	return false
}

// handleInbound inspects a packet coming out of the tunnel towards the OS.
// It returns true if the packet was a reply to one of our upstream queries.
func (e *Engine) handleInbound(pkt []byte) bool {
	p, ok := parseIP(pkt)
	if !ok || p.proto != protoUDP || !e.isDNSServer(p.src) {
		return false
	}
	sport, dport, payload, ok := parseUDP(p.l4)
	if !ok || sport != 53 {
		return false
	}
	e.mu.Lock()
	ch, ok := e.pending[dport]
	if ok {
		delete(e.pending, dport)
	}
	e.mu.Unlock()
	if !ok {
		return false
	}
	ch <- append([]byte(nil), payload...)
	return true
}

// deliverToOS is set by the tun wrapper; it writes a packet to the OS.
func (e *Engine) deliverToOS(pkt []byte) {
	if w := e.osWriter(); w != nil {
		w(pkt)
	}
}

var errNoUpstream = errors.New("no usable DNS server")

// upstream sends a raw DNS query through the tunnel and waits for the reply.
func (e *Engine) upstream(query []byte) ([]byte, error) {
	if len(e.cfg.DNSServers) == 0 {
		return nil, errNoUpstream
	}
	var lastErr error = errNoUpstream
	for try := 0; try < upstreamTries; try++ {
		server := e.cfg.DNSServers[try%len(e.cfg.DNSServers)].Unmap()
		src := e.src4
		if server.Is6() {
			src = e.src6
		}
		if !src.IsValid() {
			lastErr = errNoUpstream
			continue
		}
		ch := make(chan []byte, 1)
		var port uint16
		e.mu.Lock()
		for {
			port = uint16(49152 + rand.IntN(16384))
			if _, busy := e.pending[port]; !busy {
				break
			}
		}
		e.pending[port] = ch
		e.mu.Unlock()

		pkt := buildUDP(netip.AddrPortFrom(src, port), netip.AddrPortFrom(server, 53), query)
		select {
		case e.inject <- pkt:
		case <-e.closed:
			return nil, errClosed
		}
		select {
		case resp := <-ch:
			return resp, nil
		case <-time.After(upstreamTimeout):
			lastErr = errors.New("DNS server did not answer through the tunnel")
		case <-e.closed:
			return nil, errClosed
		}
		e.mu.Lock()
		delete(e.pending, port)
		e.mu.Unlock()
	}
	return nil, lastErr
}

// Failure is a recent fail-closed event for the status view (D20).
type Failure struct {
	Domain string `json:"domain"`
	Reason string `json:"reason"`
	AtUnix int64  `json:"atUnix"`
}

// DomainStatus is what the status view shows per matched domain (D19).
type DomainStatus struct {
	Domain   string   `json:"domain"`
	IPs      []string `json:"ips"`
	Warnings []string `json:"warnings,omitempty"`
	Error    string   `json:"error,omitempty"`
	AtUnix   int64    `json:"atUnix"`
}

func (e *Engine) recordFailure(domain, reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failures = append(e.failures, Failure{Domain: domain, Reason: reason, AtUnix: time.Now().Unix()})
	if len(e.failures) > maxFailures {
		e.failures = e.failures[len(e.failures)-maxFailures:]
	}
	e.logf("fail-closed: %s", reason)
}

func (e *Engine) recordDomain(ds DomainStatus) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ds.AtUnix = time.Now().Unix()
	if prev, ok := e.domains[ds.Domain]; ok && ds.Error == "" && len(ds.IPs) == 0 {
		// An empty answer (e.g. synthesized AAAA) shouldn't hide earlier IPs.
		prev.AtUnix = ds.AtUnix
		return
	}
	e.domains[ds.Domain] = &ds
	if len(e.domains) > maxDomainStatus {
		var oldest string
		var oldestAt int64 = 1 << 62
		for k, v := range e.domains {
			if v.AtUnix < oldestAt {
				oldest, oldestAt = k, v.AtUnix
			}
		}
		delete(e.domains, oldest)
	}
}
