package engine

import (
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Route timing (D4). A dynamic route is removed only when its DNS TTL has
// passed AND no packet has used it for idleTimeout, so long-lived connections
// are never moved out of the tunnel mid-stream.
const (
	ttlFloor     = 60 * time.Second
	idleTimeout  = 5 * time.Minute
	janitorEvery = 30 * time.Second
	applyTimeout = 5 * time.Second
	maxDynamic   = 2048
)

// coalesceDelay is how long the applier waits to batch route requests; a var
// so tests can shorten it.
var coalesceDelay = 10 * time.Millisecond

var (
	errTooManyRoutes = errors.New("dynamic route limit reached")
	errApplyTimeout  = errors.New("route update timed out")
	errClosed        = errors.New("engine closed")
)

// ApplyFunc installs the complete set of dynamic routes into the OS tunnel
// settings. It must block until the routes are active (D4 hold).
type ApplyFunc func(dynamic []netip.Prefix) error

type dynRoute struct {
	prefix   netip.Prefix
	domains  map[string]struct{}
	expires  time.Time
	lastUsed atomic.Int64 // unix nanos
	pending  bool         // added but not yet confirmed by an apply
}

type router struct {
	apply  ApplyFunc
	static []netip.Prefix
	now    func() time.Time

	mu      sync.Mutex
	dynamic map[netip.Prefix]*dynRoute

	// usage is an immutable snapshot of applied routes for lock-free lookup on
	// the packet hot path.
	usage atomic.Pointer[map[netip.Prefix]*dynRoute]

	reqs   chan chan error
	closed chan struct{}
	wg     sync.WaitGroup
}

func newRouter(static []netip.Prefix, apply ApplyFunc) *router {
	r := &router{
		apply:   apply,
		static:  static,
		now:     time.Now,
		dynamic: map[netip.Prefix]*dynRoute{},
		reqs:    make(chan chan error, 64),
		closed:  make(chan struct{}),
	}
	empty := map[netip.Prefix]*dynRoute{}
	r.usage.Store(&empty)
	r.wg.Add(2)
	go r.applier()
	go r.janitor()
	return r
}

func (r *router) close() {
	select {
	case <-r.closed:
	default:
		close(r.closed)
	}
	r.wg.Wait()
}

// aggregate maps an address to the prefix the engine routes: /24 for IPv4,
// /64 for IPv6 (D4).
func aggregate(ip netip.Addr) netip.Prefix {
	ip = ip.Unmap()
	bits := 64
	if ip.Is4() {
		bits = 24
	}
	p, _ := ip.Prefix(bits)
	return p
}

func (r *router) coveredByStatic(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range r.static {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// routedViaTunnel reports whether traffic to ip currently goes into the tunnel.
func (r *router) routedViaTunnel(ip netip.Addr) bool {
	if r.coveredByStatic(ip) {
		return true
	}
	_, ok := (*r.usage.Load())[aggregate(ip)]
	return ok
}

// lastUsed returns when a packet last went to ip's dynamic prefix.
func (r *router) lastUsed(ip netip.Addr) (time.Time, bool) {
	d, ok := (*r.usage.Load())[aggregate(ip)]
	if !ok {
		return time.Time{}, false
	}
	n := d.lastUsed.Load()
	if n == 0 {
		return time.Time{}, false
	}
	return time.Unix(0, n), true
}

// touch records an outbound packet to dst. Called per packet; lock-free.
func (r *router) touch(dst netip.Addr) {
	m := *r.usage.Load()
	if len(m) == 0 {
		return
	}
	d, ok := m[aggregate(dst)]
	if !ok {
		return
	}
	now := r.now().UnixNano()
	// Only write when the stored value is more than a second old.
	if now-d.lastUsed.Load() > int64(time.Second) {
		d.lastUsed.Store(now)
	}
}

// ensure makes sure every ip is routed into the tunnel, blocking until the OS
// has applied any new routes. Returns nil if nothing needed to change.
func (r *router) ensure(ips []netip.Addr, domain string, ttl time.Duration) error {
	if ttl < ttlFloor {
		ttl = ttlFloor
	}
	expires := r.now().Add(ttl)
	added := 0

	r.mu.Lock()
	for _, ip := range ips {
		if r.coveredByStatic(ip) {
			continue
		}
		p := aggregate(ip)
		if d, ok := r.dynamic[p]; ok {
			d.domains[domain] = struct{}{}
			if expires.After(d.expires) {
				d.expires = expires
			}
			if d.pending {
				added++ // still waiting on an in-flight apply; wait for it too
			}
			continue
		}
		if len(r.dynamic) >= maxDynamic {
			r.mu.Unlock()
			return errTooManyRoutes
		}
		r.dynamic[p] = &dynRoute{
			prefix:  p,
			domains: map[string]struct{}{domain: {}},
			expires: expires,
			pending: true,
		}
		added++
	}
	r.mu.Unlock()

	if added == 0 {
		return nil
	}
	done := make(chan error, 1)
	select {
	case r.reqs <- done:
	case <-r.closed:
		return errClosed
	}
	select {
	case err := <-done:
		return err
	case <-time.After(applyTimeout):
		return errApplyTimeout
	case <-r.closed:
		return errClosed
	}
}

// applier serializes and coalesces route updates: every request that arrives
// within coalesceDelay of the first is satisfied by one apply call.
func (r *router) applier() {
	defer r.wg.Done()
	for {
		var batch []chan error
		select {
		case req := <-r.reqs:
			batch = append(batch, req)
		case <-r.closed:
			return
		}
		timer := time.NewTimer(coalesceDelay)
	collect:
		for {
			select {
			case req := <-r.reqs:
				batch = append(batch, req)
			case <-timer.C:
				break collect
			case <-r.closed:
				timer.Stop()
				return
			}
		}

		r.mu.Lock()
		set := make([]netip.Prefix, 0, len(r.dynamic))
		for p := range r.dynamic {
			set = append(set, p)
		}
		r.mu.Unlock()
		slices.SortFunc(set, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })

		err := r.apply(set)

		r.mu.Lock()
		inSet := make(map[netip.Prefix]bool, len(set))
		for _, p := range set {
			inSet[p] = true
		}
		for p, d := range r.dynamic {
			if !inSet[p] {
				continue // added after the snapshot; the next batch covers it
			}
			if err == nil {
				d.pending = false
			} else if d.pending {
				delete(r.dynamic, p)
			}
		}
		snap := make(map[netip.Prefix]*dynRoute, len(r.dynamic))
		for p, d := range r.dynamic {
			if !d.pending {
				snap[p] = d
			}
		}
		r.usage.Store(&snap)
		r.mu.Unlock()

		for _, c := range batch {
			c <- err
		}
	}
}

func (r *router) janitor() {
	defer r.wg.Done()
	t := time.NewTicker(janitorEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if r.expire() {
				// Fire-and-forget: push the shrunken set to the OS.
				select {
				case r.reqs <- make(chan error, 1):
				default:
				}
			}
		case <-r.closed:
			return
		}
	}
}

// expire drops routes whose TTL has passed and which have been idle long
// enough. Returns true if anything was removed.
func (r *router) expire() bool {
	now := r.now()
	removed := false
	r.mu.Lock()
	for p, d := range r.dynamic {
		if d.pending || now.Before(d.expires) {
			continue
		}
		if last := d.lastUsed.Load(); last != 0 && now.Sub(time.Unix(0, last)) < idleTimeout {
			continue
		}
		delete(r.dynamic, p)
		removed = true
	}
	r.mu.Unlock()
	return removed
}

// RouteStatus describes one dynamic route for the live status view (D19).
type RouteStatus struct {
	Prefix         string   `json:"prefix"`
	Domains        []string `json:"domains"`
	ExpiresInSec   int      `json:"expiresInSec"`
	LastUsedSecAgo int      `json:"lastUsedSecAgo"` // -1 if never used
}

func (r *router) status() []RouteStatus {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RouteStatus, 0, len(r.dynamic))
	for _, d := range r.dynamic {
		if d.pending {
			continue
		}
		rs := RouteStatus{
			Prefix:         d.prefix.String(),
			ExpiresInSec:   max(0, int(d.expires.Sub(now).Seconds())),
			LastUsedSecAgo: -1,
		}
		for dom := range d.domains {
			rs.Domains = append(rs.Domains, dom)
		}
		slices.Sort(rs.Domains)
		if n := d.lastUsed.Load(); n != 0 {
			rs.LastUsedSecAgo = int(now.Sub(time.Unix(0, n)).Seconds())
		}
		out = append(out, rs)
	}
	slices.SortFunc(out, func(a, b RouteStatus) int {
		pa, _ := netip.ParsePrefix(a.Prefix)
		pb, _ := netip.ParsePrefix(b.Prefix)
		return pa.Addr().Compare(pb.Addr())
	})
	return out
}
