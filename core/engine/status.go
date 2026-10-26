package engine

import (
	"slices"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Status is the engine part of the live status view (D19). It lives in memory
// only and disappears with the engine.
type Status struct {
	Domains      []DomainStatus `json:"domains"`
	Routes       []RouteStatus  `json:"routes"`
	StaticRoutes []string       `json:"staticRoutes"`
	Failures     []Failure      `json:"failures"`
	DynamicMode  bool           `json:"dynamicMode"`
}

func (e *Engine) Status() Status {
	s := Status{
		Routes:      e.router.status(),
		DynamicMode: e.cfg.DynamicRoutes,
	}
	for _, p := range e.cfg.StaticRoutes {
		s.StaticRoutes = append(s.StaticRoutes, p.String())
	}
	e.mu.Lock()
	for _, d := range e.domains {
		s.Domains = append(s.Domains, *d)
	}
	s.Failures = slices.Clone(e.failures)
	e.mu.Unlock()
	slices.SortFunc(s.Domains, func(a, b DomainStatus) int { return int(b.AtUnix - a.AtUnix) })
	slices.Reverse(s.Failures)
	return s
}

// TestResult answers "does this domain actually use the tunnel?" (D24).
type TestResult struct {
	Domain  string       `json:"domain"`
	Matched bool         `json:"matched"`
	Rcode   string       `json:"rcode,omitempty"`
	Error   string       `json:"error,omitempty"`
	IPs     []TestedAddr `json:"ips"`
}

type TestedAddr struct {
	IP             string `json:"ip"`
	ViaTunnel      bool   `json:"viaTunnel"`
	InAllowedIPs   bool   `json:"inAllowedIPs"`
	LastUsedSecAgo int    `json:"lastUsedSecAgo"` // -1 if no traffic seen yet
}

// TestDomain resolves name through the same path an app's query would take
// (including route installation) and reports where its traffic goes.
func (e *Engine) TestDomain(name string) TestResult {
	name = normalizeName(name)
	res := TestResult{Domain: name, Matched: e.matches(name)}
	types := []dnsmessage.Type{dnsmessage.TypeA}
	if e.hasV6 {
		types = append(types, dnsmessage.TypeAAAA)
	}
	now := time.Now()
	for _, t := range types {
		q, err := buildQuery(name, t)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		resp := e.Resolve(q)
		if resp == nil {
			res.Error = "no answer"
			return res
		}
		if rc, ok := rcodeOf(resp); ok && t == dnsmessage.TypeA {
			res.Rcode = rc.String()
		}
		ips, _ := answerIPs(resp)
		for _, ip := range ips {
			ta := TestedAddr{
				IP:             ip.String(),
				ViaTunnel:      e.router.routedViaTunnel(ip),
				InAllowedIPs:   len(e.cfg.AllowedIPs) == 0 || e.inAllowedIPs(ip),
				LastUsedSecAgo: -1,
			}
			if last, ok := e.router.lastUsed(ip); ok {
				ta.LastUsedSecAgo = int(now.Sub(last).Seconds())
			}
			res.IPs = append(res.IPs, ta)
		}
	}
	if !res.Matched {
		res.Error = "not in this tunnel's Domains, so the system resolves it normally"
	}
	return res
}
