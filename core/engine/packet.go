package engine

import (
	"encoding/binary"
	"net/netip"
)

const (
	protoTCP = 6
	protoUDP = 17
)

// ipPacket is a minimal view of an IPv4/IPv6 packet. Only what the engine
// needs: addresses, transport protocol and the transport payload.
type ipPacket struct {
	proto byte
	src   netip.Addr
	dst   netip.Addr
	l4    []byte
}

// parseIP parses an IPv4 or IPv6 packet. IPv4 fragments and IPv6 extension
// headers are reported as not ok; DNS over UDP never needs them in practice.
func parseIP(pkt []byte) (p ipPacket, ok bool) {
	if len(pkt) < 1 {
		return p, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return p, false
		}
		ihl := int(pkt[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(pkt[2:4]))
		if ihl < 20 || total < ihl || total > len(pkt) {
			return p, false
		}
		// More-fragments flag or a non-zero fragment offset.
		if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
			return p, false
		}
		p.proto = pkt[9]
		p.src = netip.AddrFrom4([4]byte(pkt[12:16]))
		p.dst = netip.AddrFrom4([4]byte(pkt[16:20]))
		p.l4 = pkt[ihl:total]
		return p, true
	case 6:
		if len(pkt) < 40 {
			return p, false
		}
		plen := int(binary.BigEndian.Uint16(pkt[4:6]))
		if 40+plen > len(pkt) {
			return p, false
		}
		p.proto = pkt[6]
		p.src = netip.AddrFrom16([16]byte(pkt[8:24]))
		p.dst = netip.AddrFrom16([16]byte(pkt[24:40]))
		p.l4 = pkt[40 : 40+plen]
		return p, true
	}
	return p, false
}

// dstAddr returns the destination address of a packet without fully parsing it.
// Used on the hot path for route usage tracking.
func dstAddr(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) >= 20 {
			return netip.AddrFrom4([4]byte(pkt[16:20])), true
		}
	case 6:
		if len(pkt) >= 40 {
			return netip.AddrFrom16([16]byte(pkt[24:40])), true
		}
	}
	return netip.Addr{}, false
}

// parseUDP splits a UDP datagram into ports and payload.
func parseUDP(l4 []byte) (sport, dport uint16, payload []byte, ok bool) {
	if len(l4) < 8 {
		return 0, 0, nil, false
	}
	ulen := int(binary.BigEndian.Uint16(l4[4:6]))
	if ulen < 8 || ulen > len(l4) {
		return 0, 0, nil, false
	}
	return binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4]), l4[8:ulen], true
}

// buildUDP builds a complete IPv4 or IPv6 packet carrying a UDP datagram.
// src and dst must be the same address family.
func buildUDP(src, dst netip.AddrPort, payload []byte) []byte {
	udpLen := 8 + len(payload)
	var pkt []byte
	var l4 []byte
	if src.Addr().Is4() {
		pkt = make([]byte, 20+udpLen)
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
		pkt[8] = 64
		pkt[9] = protoUDP
		s, d := src.Addr().As4(), dst.Addr().As4()
		copy(pkt[12:16], s[:])
		copy(pkt[16:20], d[:])
		binary.BigEndian.PutUint16(pkt[10:12], ^foldChecksum(sum(pkt[:20], 0)))
		l4 = pkt[20:]
	} else {
		pkt = make([]byte, 40+udpLen)
		pkt[0] = 0x60
		binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen))
		pkt[6] = protoUDP
		pkt[7] = 64
		s, d := src.Addr().As16(), dst.Addr().As16()
		copy(pkt[8:24], s[:])
		copy(pkt[24:40], d[:])
		l4 = pkt[40:]
	}
	binary.BigEndian.PutUint16(l4[0:2], src.Port())
	binary.BigEndian.PutUint16(l4[2:4], dst.Port())
	binary.BigEndian.PutUint16(l4[4:6], uint16(udpLen))
	copy(l4[8:], payload)
	cs := ^foldChecksum(sum(l4, pseudoHeaderSum(src.Addr(), dst.Addr(), protoUDP, udpLen)))
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(l4[6:8], cs)
	return pkt
}

func pseudoHeaderSum(src, dst netip.Addr, proto byte, length int) uint32 {
	var acc uint32
	s, d := src.AsSlice(), dst.AsSlice()
	acc = sum(s, acc)
	acc = sum(d, acc)
	acc += uint32(proto)
	acc += uint32(length)
	return acc
}

func sum(b []byte, acc uint32) uint32 {
	for len(b) >= 2 {
		acc += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		acc += uint32(b[0]) << 8
	}
	return acc
}

func foldChecksum(acc uint32) uint16 {
	for acc>>16 != 0 {
		acc = (acc & 0xffff) + (acc >> 16)
	}
	return uint16(acc)
}
