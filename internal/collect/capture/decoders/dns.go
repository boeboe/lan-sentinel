package decoders

import (
	"errors"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"lan-sentinel/internal/observation"
)

// Limits on what one mDNS packet contributes.
const (
	maxRecords  = 64 // resource records read per message
	maxServices = 16 // service types kept per packet
)

// mdnsInfo is what one mDNS response says about its sender.
type mdnsInfo struct {
	addrs    []mdnsAddr        // A and AAAA records in packet order
	services map[string]string // service type → port ("" if no SRV)
	targets  []string          // SRV target hosts
	txt      []string
}

type mdnsAddr struct {
	name string
	ip   netip.Addr
}

// mdns decodes an mDNS response (FR-PA-4): A and AAAA records name the
// sender's addresses; PTR, SRV and TXT records describe its services. An
// mDNS responder answers for itself, so every address record is evidence
// for the frame's source MAC. One hostname per packet is kept, the one
// whose address is the packet's source (else the first), so an alias does
// not flip the host's mDNS name back and forth.
func (f *frame) mdns(src netip.Addr, b []byte) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil || !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		return
	}
	if err := p.SkipAllQuestions(); err != nil {
		return
	}
	info := mdnsInfo{services: map[string]string{}}
	n := 0
	// next reads a section's record headers, skip skips a record of a type
	// the decoder does not read.
	visit := func(next func() (dnsmessage.ResourceHeader, error), skip func() error) bool {
		for n < maxRecords {
			rh, err := next()
			if err != nil {
				return errors.Is(err, dnsmessage.ErrSectionDone)
			}
			n++
			if !info.record(&p, rh, skip) {
				return false
			}
		}
		return true
	}
	// Records read before a malformed one are kept.
	if visit(p.AnswerHeader, p.SkipAnswer) && n < maxRecords && p.SkipAllAuthorities() == nil {
		visit(p.AdditionalHeader, p.SkipAdditional)
	}
	f.mdnsObservations(src, info)
}

// record reads one resource record into info, skipping unknown types with
// skip; false stops parsing.
func (info *mdnsInfo) record(p *dnsmessage.Parser, rh dnsmessage.ResourceHeader, skip func() error) bool {
	owner := rh.Name.String()
	switch rh.Type {
	case dnsmessage.TypeA:
		r, err := p.AResource()
		if err != nil {
			return false
		}
		info.addrs = append(info.addrs, mdnsAddr{hostname(owner), netip.AddrFrom4(r.A)})
	case dnsmessage.TypeAAAA:
		r, err := p.AAAAResource()
		if err != nil {
			return false
		}
		info.addrs = append(info.addrs, mdnsAddr{hostname(owner), netip.AddrFrom16(r.AAAA)})
	case dnsmessage.TypePTR:
		r, err := p.PTRResource()
		if err != nil {
			return false
		}
		info.service(serviceType(r.PTR.String()), "")
	case dnsmessage.TypeSRV:
		r, err := p.SRVResource()
		if err != nil {
			return false
		}
		info.service(serviceType(owner), strconv.Itoa(int(r.Port)))
		if t := hostname(r.Target.String()); t != "" && !slices.Contains(info.targets, t) {
			info.targets = append(info.targets, t)
		}
	case dnsmessage.TypeTXT:
		r, err := p.TXTResource()
		if err != nil {
			return false
		}
		for _, s := range r.TXT {
			if t := text([]byte(s), maxText); t != "" {
				info.txt = append(info.txt, t)
			}
		}
	default:
		if err := skip(); err != nil {
			return false
		}
	}
	return true
}

func (info *mdnsInfo) service(svc, port string) {
	if svc == "" {
		return
	}
	if _, ok := info.services[svc]; !ok && len(info.services) >= maxServices {
		return
	}
	if port != "" || info.services[svc] == "" {
		info.services[svc] = port
	}
}

// serviceType extracts "_http._tcp" from "Instance._http._tcp.local.",
// "_http._tcp.local." or "_printer._sub._http._tcp.local.".
func serviceType(name string) string {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := len(labels) - 1; i > 0; i-- {
		if (labels[i] == "_tcp" || labels[i] == "_udp") && strings.HasPrefix(labels[i-1], "_") && len(labels[i-1]) > 1 {
			return text([]byte(labels[i-1]+"."+labels[i]), 64)
		}
	}
	return ""
}

func (f *frame) mdnsObservations(src netip.Addr, info mdnsInfo) {
	meta := info.meta()
	name := ""
	for _, a := range info.addrs {
		if a.ip == src {
			name = a.name
			break
		}
	}
	if name == "" && len(info.addrs) > 0 {
		name = info.addrs[0].name
	}
	emitted := 0
	for _, a := range info.addrs {
		o := observation.Observation{Source: observation.PassiveMDNS, MAC: f.src, IP: a.ip, Meta: meta}
		if a.name == name {
			o.Hostname, o.NameType = name, observation.NameMDNS
		}
		before := len(f.out)
		f.add(o)
		emitted += len(f.out) - before
	}
	if emitted == 0 && (len(info.services) > 0 || name != "") {
		// Services without usable addresses: the sender is still evidence.
		o := observation.Observation{Source: observation.PassiveMDNS, MAC: f.src, IP: src, Meta: meta}
		if name == "" && len(info.targets) == 1 {
			name = info.targets[0]
		}
		o.Hostname, o.NameType = name, observation.NameMDNS
		f.add(o)
	}
}

// meta summarises services: "services" lists the service types,
// "service_ports" the SRV ports and "txt" the TXT strings.
func (info mdnsInfo) meta() map[string]string {
	if len(info.services) == 0 && len(info.txt) == 0 {
		return nil
	}
	m := map[string]string{}
	var svcs, ports []string
	for s, port := range info.services {
		svcs = append(svcs, s)
		if port != "" {
			ports = append(ports, s+"="+port)
		}
	}
	sort.Strings(svcs)
	sort.Strings(ports)
	if len(svcs) > 0 {
		m["services"] = strings.Join(svcs, ",")
	}
	if len(ports) > 0 {
		m["service_ports"] = strings.Join(ports, ",")
	}
	if len(info.txt) > 0 {
		m["txt"] = text([]byte(strings.Join(info.txt, ";")), maxText)
	}
	return m
}

// dns decodes a unicast DNS response. Only PTR answers to reverse lookups
// become observations (name type dns_ptr): they say which name an address
// has, without MAC evidence, so the correlator attaches them to the host
// holding that address (docs/DATA_MODEL.md §5.1).
func (f *frame) dns(b []byte) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil || !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		return
	}
	if err := p.SkipAllQuestions(); err != nil {
		return
	}
	seen := map[netip.Addr]bool{}
	for range maxRecords {
		rh, err := p.AnswerHeader()
		if err != nil {
			return
		}
		if rh.Type != dnsmessage.TypePTR {
			if err := p.SkipAnswer(); err != nil {
				return
			}
			continue
		}
		r, err := p.PTRResource()
		if err != nil {
			return
		}
		ip, ok := reverseAddr(rh.Name.String())
		name := hostname(r.PTR.String())
		if !ok || name == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		f.add(observation.Observation{Source: observation.PassiveDNS, IP: ip, Hostname: name, NameType: observation.NameDNSPTR})
	}
}

// reverseAddr parses "4.3.2.1.in-addr.arpa." and the nibble form under
// ip6.arpa.
func reverseAddr(name string) (netip.Addr, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if rest, ok := strings.CutSuffix(name, ".in-addr.arpa"); ok {
		parts := strings.Split(rest, ".")
		if len(parts) != 4 {
			return netip.Addr{}, false
		}
		slices.Reverse(parts)
		ip, err := netip.ParseAddr(strings.Join(parts, "."))
		return ip, err == nil
	}
	if rest, ok := strings.CutSuffix(name, ".ip6.arpa"); ok {
		nibbles := strings.Split(rest, ".")
		if len(nibbles) != 32 {
			return netip.Addr{}, false
		}
		var b [16]byte
		for i, n := range nibbles {
			v, err := strconv.ParseUint(n, 16, 8)
			if err != nil || len(n) != 1 {
				return netip.Addr{}, false
			}
			pos := 31 - i // nibbles are listed least significant first
			b[pos/2] |= byte(v) << (4 * (1 - pos%2))
		}
		return netip.AddrFrom16(b), true
	}
	return netip.Addr{}, false
}
