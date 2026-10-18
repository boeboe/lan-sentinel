package decoders

import (
	"bytes"
	"net/netip"
	"strings"

	"lan-sentinel/internal/observation"
)

// Limits on an SSDP message: its size and its header lines.
const (
	maxSSDP        = 2048
	maxSSDPHeaders = 32
	maxSSDPUUID    = 64
)

// ssdp decodes an SSDP message (UPnP Device Architecture 2.0 §1): a NOTIFY
// ssdp:alive or ssdp:update a device multicasts, or a device's answer to an
// M-SEARCH (seen on a mirror port). Only the root device and device types
// are kept: service types and the bare uuid add nothing about what the
// device is. A search, or an ssdp:byebye, says nothing about the sender.
// The evidence is the frame's source MAC and address; LOCATION may name
// another address and is only kept in meta.
func (f *frame) ssdp(src netip.Addr, b []byte) {
	if len(b) > maxSSDP {
		b = b[:maxSSDP]
	}
	lines := bytes.SplitN(b, []byte("\n"), maxSSDPHeaders+1)
	first := string(bytes.TrimSpace(lines[0]))
	var kind string
	switch {
	case strings.HasPrefix(first, "NOTIFY * HTTP/1."):
		kind = "notify"
	case strings.HasPrefix(first, "HTTP/1.1 200"):
		kind = "response"
	default:
		return
	}
	headers := map[string]string{}
	for _, l := range lines[1:] {
		l = bytes.TrimSpace(l)
		if len(l) == 0 {
			break
		}
		k, v, ok := bytes.Cut(l, []byte(":"))
		if !ok {
			continue
		}
		key := strings.ToUpper(string(bytes.TrimSpace(k)))
		if _, dup := headers[key]; !dup {
			headers[key] = text(bytes.TrimSpace(v), maxText)
		}
	}
	target := headers["NT"]
	if kind == "response" {
		target = headers["ST"]
	} else if nts := strings.ToLower(headers["NTS"]); nts != "ssdp:alive" && nts != "ssdp:update" {
		return
	}
	if !ssdpDeviceType(target) {
		return
	}
	meta := map[string]string{"ssdp": kind, "nt": target}
	if v := headers["SERVER"]; v != "" {
		meta["server"] = v
	}
	if v := headers["LOCATION"]; v != "" {
		meta["location"] = v
	}
	if u := ssdpUUID(headers["USN"]); u != "" {
		meta["uuid"] = u
	}
	f.add(observation.Observation{Source: observation.PassiveSSDP, MAC: f.src, IP: src, Meta: meta})
}

// ssdpDeviceType reports a notification or search target that describes a
// device: upnp:rootdevice or a device type URN (urn:<domain>:device:<type>:<v>).
func ssdpDeviceType(nt string) bool {
	nt = strings.ToLower(nt)
	return nt == "upnp:rootdevice" || strings.HasPrefix(nt, "urn:") && strings.Contains(nt, ":device:")
}

// ssdpUUID is the device UUID of a USN: "uuid:<id>" or "uuid:<id>::<type>".
func ssdpUUID(usn string) string {
	if len(usn) < 5 || !strings.EqualFold(usn[:5], "uuid:") {
		return ""
	}
	id, _, _ := strings.Cut(usn[5:], "::")
	if len(id) > maxSSDPUUID {
		return ""
	}
	return strings.ToLower(id)
}
