package engine

import (
	"net/netip"
	"testing"
)

func TestBuildParseUDPRoundTrip(t *testing.T) {
	for _, pair := range [][2]string{
		{"10.8.0.2:5353", "10.8.0.1:53"},
		{"[fd00::2]:5353", "[fd00::1]:53"},
	} {
		src, dst := netip.MustParseAddrPort(pair[0]), netip.MustParseAddrPort(pair[1])
		pkt := buildUDP(src, dst, []byte("hello"))
		p, ok := parseIP(pkt)
		if !ok || p.proto != protoUDP || p.src != src.Addr() || p.dst != dst.Addr() {
			t.Fatalf("parse %v: %+v", pair, p)
		}
		sp, dp, payload, ok := parseUDP(p.l4)
		if !ok || sp != src.Port() || dp != dst.Port() || string(payload) != "hello" {
			t.Fatalf("udp %v: %d %d %q", pair, sp, dp, payload)
		}
		// A correct checksum sums (with the pseudo header) to 0xffff.
		if got := foldChecksum(sum(p.l4, pseudoHeaderSum(src.Addr(), dst.Addr(), protoUDP, len(p.l4)))); got != 0xffff {
			t.Fatalf("udp checksum invalid for %v: %#x", pair, got)
		}
		if src.Addr().Is4() {
			if got := foldChecksum(sum(pkt[:20], 0)); got != 0xffff {
				t.Fatalf("ipv4 header checksum invalid: %#x", got)
			}
		}
	}
}

func TestParseRejectsFragments(t *testing.T) {
	pkt := buildUDP(netip.MustParseAddrPort("1.1.1.1:1"), netip.MustParseAddrPort("2.2.2.2:2"), []byte("x"))
	pkt[6] |= 0x20 // more fragments
	if _, ok := parseIP(pkt); ok {
		t.Fatal("fragment accepted")
	}
}
