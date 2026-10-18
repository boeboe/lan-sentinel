package decoders

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"lan-sentinel/internal/observation"
)

// Limits on a WS-Discovery message: its size, the XML tokens read and their
// nesting. A Hello is 1–3 KB.
const (
	maxWSD       = 16 << 10
	maxWSDTokens = 2000
	maxWSDDepth  = 32
)

// onvifScope is the prefix of the ONVIF scopes (ONVIF Core §7.3.2.2).
const onvifScope = "onvif://www.onvif.org/"

// wsd decodes a WS-Discovery message (OASIS WS-Discovery 1.1, and the
// 2005/04 draft that Windows and ONVIF devices use): a Hello a device
// multicasts when it joins, or the ProbeMatch or ResolveMatch it answers
// with (seen on a mirror port). Probes, Resolves and Byes say nothing about
// the sender. Kept in meta: the endpoint address, the types (their local
// names: ONVIF's NetworkVideoTransmitter, a printer's PrintDeviceType), the
// first transport address, and the ONVIF scopes that name the hardware, the
// device and its ONVIF types. The evidence is the frame's source MAC and
// address; a transport address may name another address and is only kept.
func (f *frame) wsd(src netip.Addr, b []byte) {
	if len(b) > maxWSD {
		return
	}
	m, ok := parseWSD(b)
	if !ok {
		return
	}
	meta := map[string]string{"wsd": m.kind}
	setText(meta, "endpoint", []byte(m.endpoint))
	setText(meta, "types", []byte(qnameLocals(m.types)))
	if x, _, _ := strings.Cut(strings.TrimSpace(m.xaddrs), " "); x != "" {
		setText(meta, "xaddr", []byte(x))
	}
	var onvifTypes []string
	for _, s := range strings.Fields(m.scopes) {
		if !strings.HasPrefix(strings.ToLower(s), onvifScope) {
			continue
		}
		key, value, _ := strings.Cut(s[len(onvifScope):], "/") // the value in its own case
		if v, err := url.PathUnescape(value); err == nil {
			value = v
		}
		switch strings.ToLower(key) {
		case "hardware":
			setText(meta, "onvif_hardware", []byte(value))
		case "name":
			setText(meta, "onvif_name", []byte(value))
		case "type":
			if value != "" && !slices.Contains(onvifTypes, value) {
				onvifTypes = append(onvifTypes, value)
			}
		}
	}
	setText(meta, "onvif_types", []byte(strings.Join(onvifTypes, ",")))
	f.add(observation.Observation{Source: observation.PassiveWSD, MAC: f.src, IP: src, Meta: meta})
}

type wsdMessage struct {
	kind                            string // hello, probe_match, resolve_match
	endpoint, types, scopes, xaddrs string
}

// wsdMatches are the body elements that describe the sender.
var wsdMatches = map[string]string{"Hello": "hello", "ProbeMatch": "probe_match", "ResolveMatch": "resolve_match"}

// parseWSD reads the first Hello, ProbeMatch or ResolveMatch of a SOAP
// envelope by element local names, so either WS-Discovery namespace works.
// It reads a bounded number of tokens; Go's XML decoder expands no
// external or user-defined entities.
func parseWSD(b []byte) (wsdMessage, bool) {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = false
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil } // text() cleans the result
	var (
		m     wsdMessage
		path  []string
		match int // depth of the matched element; -1 once it has ended
	)
	for range maxWSDTokens {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			path = append(path, t.Name.Local)
			if len(path) > maxWSDDepth {
				return wsdMessage{}, false
			}
			if kind, ok := wsdMatches[t.Name.Local]; ok && match == 0 {
				m.kind, match = kind, len(path)
			}
		case xml.EndElement:
			if len(path) == 0 {
				continue
			}
			if len(path) == match {
				match = -1
			}
			path = path[:len(path)-1]
		case xml.CharData:
			if match <= 0 || len(path) <= match {
				continue
			}
			var field *string
			switch path[len(path)-1] {
			case "Types":
				field = &m.types
			case "Scopes":
				field = &m.scopes
			case "XAddrs":
				field = &m.xaddrs
			case "Address":
				if path[len(path)-2] == "EndpointReference" {
					field = &m.endpoint
				}
			}
			if field != nil && len(*field) < maxWSD {
				*field += string(t)
			}
		}
	}
	return m, m.kind != ""
}

// qnameLocals turns space-separated QNames ("dn:NetworkVideoTransmitter
// tds:Device") into their local names, once each, comma-separated.
func qnameLocals(qnames string) string {
	var out []string
	for _, q := range strings.Fields(qnames) {
		if i := strings.LastIndexByte(q, ':'); i >= 0 {
			q = q[i+1:]
		}
		if q != "" && !slices.Contains(out, q) {
			out = append(out, q)
		}
	}
	return strings.Join(out, ",")
}
