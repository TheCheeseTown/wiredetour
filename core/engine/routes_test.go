package engine

import (
	"net/netip"
	"testing"
	"time"
)

func TestAggregate(t *testing.T) {
	cases := map[string]string{
		"93.184.216.34":         "93.184.216.0/24",
		"::ffff:1.2.3.4":        "1.2.3.0/24",
		"2606:2800:220:1::1946": "2606:2800:220:1::/64",
	}
	for in, want := range cases {
		if got := aggregate(netip.MustParseAddr(in)); got.String() != want {
			t.Errorf("aggregate(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestExpireNeedsTTLAndIdle(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	r := newRouter(nil, func([]netip.Prefix) error { return nil })
	defer r.close()
	r.now = func() time.Time { return now }

	ip := netip.MustParseAddr("1.2.3.4")
	if err := r.ensure([]netip.Addr{ip}, "a.test", 10*time.Second); err != nil {
		t.Fatal(err)
	}
	// TTL is floored to 60s.
	now = now.Add(59 * time.Second)
	if r.expire() {
		t.Fatal("expired before TTL floor")
	}
	// Recently used: survives past TTL.
	r.touch(ip)
	now = now.Add(2 * time.Minute)
	if r.expire() {
		t.Fatal("expired while in use")
	}
	now = now.Add(idleTimeout)
	if !r.expire() {
		t.Fatal("did not expire after TTL + idle")
	}
}

func TestRouteLimit(t *testing.T) {
	old := coalesceDelay
	coalesceDelay = 0
	t.Cleanup(func() { coalesceDelay = old })
	r := newRouter(nil, func([]netip.Prefix) error { return nil })
	defer r.close()
	for i := 0; i < maxDynamic; i++ {
		ip := netip.AddrFrom4([4]byte{11, byte(i >> 8), byte(i), 1})
		if err := r.ensure([]netip.Addr{ip}, "x", time.Minute); err != nil {
			t.Fatalf("route %d: %v", i, err)
		}
	}
	if err := r.ensure([]netip.Addr{netip.MustParseAddr("12.0.0.1")}, "x", time.Minute); err != errTooManyRoutes {
		t.Fatalf("got %v, want limit error", err)
	}
}

func TestConcurrentEnsureCoalesces(t *testing.T) {
	calls := 0
	r := newRouter(nil, func([]netip.Prefix) error { calls++; return nil })
	defer r.close()
	done := make(chan error)
	for i := 0; i < 20; i++ {
		go func(i int) {
			done <- r.ensure([]netip.Addr{netip.AddrFrom4([4]byte{20, 0, byte(i), 1})}, "x", time.Minute)
		}(i)
	}
	for i := 0; i < 20; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if calls >= 20 {
		t.Fatalf("expected coalescing, got %d applies", calls)
	}
}
