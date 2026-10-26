package engine

import (
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Resolve answers one raw DNS query and returns the raw response, or nil if
// the query is unparseable and should be dropped. For matched domains it
// blocks until any needed routes are active (D4) and fails closed (D20).
func (e *Engine) Resolve(query []byte) []byte {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil || hdr.Response {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	name := normalizeName(q.Name.String())

	if suffixMatch(name, CanaryDomain) {
		return reply(hdr, q, dnsmessage.RCodeNameError)
	}
	matched := e.matches(name)
	if matched && q.Type == dnsmessage.TypeAAAA && !e.hasV6 {
		// No IPv6 in the tunnel: hide AAAA so apps fall back to IPv4 (D8).
		return reply(hdr, q, dnsmessage.RCodeSuccess)
	}

	resp, err := e.upstream(query)
	if err != nil {
		if matched {
			e.recordFailure(name, err.Error())
			e.recordDomain(DomainStatus{Domain: name, Error: err.Error()})
		}
		return reply(hdr, q, dnsmessage.RCodeServerFailure)
	}
	if len(resp) > 2 {
		// Clear TC: TCP DNS is dropped (see handleOutbound), so a partial
		// answer is better than a retry that can never succeed.
		resp[2] &^= 0x02
	}
	if !matched {
		return resp
	}

	ips, ttl := answerIPs(resp)
	if !e.hasV6 {
		ips = filterV4(ips)
	}
	ds := DomainStatus{Domain: name}
	for _, ip := range ips {
		ds.IPs = append(ds.IPs, ip.String())
	}

	if e.cfg.DynamicRoutes {
		if err := e.router.ensure(ips, name, ttl); err != nil {
			e.recordFailure(name, err.Error())
			ds.Error = err.Error()
			e.recordDomain(ds)
			return reply(hdr, q, dnsmessage.RCodeServerFailure)
		}
	} else {
		for _, ip := range ips {
			if !e.router.coveredByStatic(ip) {
				ds.Warnings = append(ds.Warnings, fmt.Sprintf("%s is outside Networks, so it does not use the tunnel", ip))
			}
		}
	}
	for _, ip := range ips {
		if len(e.cfg.AllowedIPs) > 0 && !e.inAllowedIPs(ip) {
			ds.Warnings = append(ds.Warnings, fmt.Sprintf("%s is outside the peer's AllowedIPs and will be dropped", ip))
		}
	}
	if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA {
		e.recordDomain(ds)
	}
	return resp
}

// reply builds a response with no answers, echoing the question.
func reply(hdr dnsmessage.Header, q dnsmessage.Question, rcode dnsmessage.RCode) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 hdr.ID,
		Response:           true,
		OpCode:             hdr.OpCode,
		RecursionDesired:   hdr.RecursionDesired,
		RecursionAvailable: true,
		RCode:              rcode,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil
	}
	if err := b.Question(q); err != nil {
		return nil
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// answerIPs extracts A/AAAA addresses from a response's answer section along
// with the smallest TTL among them.
func answerIPs(resp []byte) ([]netip.Addr, time.Duration) {
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return nil, 0
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, 0
	}
	var ips []netip.Addr
	var minTTL uint32
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return ips, time.Duration(minTTL) * time.Second
			}
			ips = append(ips, netip.AddrFrom4(r.A))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return ips, time.Duration(minTTL) * time.Second
			}
			ips = append(ips, netip.AddrFrom16(r.AAAA))
		default:
			if err := p.SkipAnswer(); err != nil {
				return ips, time.Duration(minTTL) * time.Second
			}
			continue
		}
		if minTTL == 0 || h.TTL < minTTL {
			minTTL = h.TTL
		}
	}
	return ips, time.Duration(minTTL) * time.Second
}

func filterV4(ips []netip.Addr) []netip.Addr {
	out := ips[:0]
	for _, ip := range ips {
		if ip.Unmap().Is4() {
			out = append(out, ip.Unmap())
		}
	}
	return out
}

// buildQuery builds a recursive query for name/type, used by TestDomain.
func buildQuery(name string, t dnsmessage.Type) ([]byte, error) {
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: uint16(time.Now().UnixNano()), RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: t, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

func rcodeOf(resp []byte) (dnsmessage.RCode, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return 0, false
	}
	return h.RCode, true
}
