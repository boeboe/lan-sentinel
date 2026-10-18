package identify

import (
	"slices"
	"strings"

	"lan-sentinel/internal/observation"
)

// The identifiers of the LAN discovery protocols (NetBIOS, CDP, SSDP,
// WS-Discovery). Like the others they read evidence already captured and
// claim only what the device states about itself (DATA_MODEL.md §5.7).

// netbiosIdentifier reads what Windows hosts and Samba servers announce
// over NetBIOS: the workgroup or domain they belong to, the roles their
// browser announcements and group names state, and, for Windows, the OS
// version a host announcement reports.
type netbiosIdentifier struct{}

func (netbiosIdentifier) Name() string { return "netbios" }

func (netbiosIdentifier) Identify(o observation.Observation) []Claim {
	if o.Source != observation.PassiveNetBIOS {
		return nil
	}
	var out []Claim
	if w := o.Meta["workgroup"]; w != "" {
		out = append(out, current(FieldWorkgroup, w, 0.7, "netbios", o.Meta["netbios"]))
	}
	types := strings.Split(o.Meta["server_type"], ",")
	has := func(t string) bool { return slices.Contains(types, t) }
	windows := has("nt") && !has("unix") // Samba announces SV_TYPE_SERVER_UNIX
	ev := []string{"server_type", o.Meta["server_type"]}
	switch {
	case o.Meta["role"] == "domain_controller":
		out = append(out, claim(FieldDeviceType, "Domain controller", 0.6, "netbios", o.Meta["netbios"], "role", o.Meta["role"]))
	case has("domain_controller") || has("backup_domain_controller"):
		out = append(out, claim(FieldDeviceType, "Domain controller", 0.6, ev...))
	case has("server_nt"):
		out = append(out, claim(FieldDeviceType, "Server", 0.5, ev...))
	case windows && has("workstation"):
		out = append(out, claim(FieldDeviceType, "Computer", 0.4, ev...))
	}
	if windows {
		out = append(out, claim(FieldOS, "Windows", 0.6, ev...))
		if v := o.Meta["os_version"]; v != "" {
			out = append(out, current(FieldOSVersion, v, 0.6, append(ev, "os_version", v)...))
		}
	}
	return out
}

// cdpIdentifier reads a CDP advertisement: the capabilities the device
// states, its platform (the model) and the first line of its software
// version (the firmware).
type cdpIdentifier struct{}

func (cdpIdentifier) Name() string { return "cdp" }

// cdpRoles maps a capability to a device type, most specific first: a
// router that also switches is a router, as for LLDP.
var cdpRoles = []struct{ capability, deviceType string }{
	{"phone", "IP phone"},
	{"router", "Router"},
	{"switch", "Switch"},
	{"bridge", "Switch"},
}

func (cdpIdentifier) Identify(o observation.Observation) []Claim {
	if o.Source != observation.PassiveCDP {
		return nil
	}
	var out []Claim
	caps := strings.Split(o.Meta["capabilities"], ",")
	for _, r := range cdpRoles {
		if slices.Contains(caps, r.capability) {
			out = append(out, claim(FieldDeviceType, r.deviceType, 0.8, "capabilities", o.Meta["capabilities"]))
			break
		}
	}
	if p := o.Meta["platform"]; p != "" {
		out = append(out, claim(FieldModel, p, 0.8, "platform", p))
	}
	if s := o.Meta["software"]; s != "" {
		out = append(out, current(FieldFirmware, s, 0.8, "software", s))
	}
	return out
}

// ssdpIdentifier reads an SSDP announcement: the device type its URN
// states, for the few that are distinctive (a Basic device says nothing),
// and the operating system, the first token of its SERVER header
// ("OS/version UPnP/2.0 product/version", UDA 2.0 §1.2.2).
type ssdpIdentifier struct{}

func (ssdpIdentifier) Name() string { return "ssdp" }

// ssdpDeviceTypes maps the type of a device URN (lower case) to a device
// type.
var ssdpDeviceTypes = map[string]struct {
	deviceType string
	confidence float64
}{
	"internetgatewaydevice": {"Router", 0.6},
	"wlanaccesspointdevice": {"Access point", 0.6},
	"mediarenderer":         {"Media player", 0.6},
	"mediaserver":           {"Media server", 0.5},
	"printer":               {"Printer", 0.6},
	"scanner":               {"Scanner", 0.6},
	"digitalsecuritycamera": {"Camera", 0.6},
	"dial":                  {"Media player", 0.6}, // urn:dial-multiscreen-org:device:dial
	"zoneplayer":            {"Speaker", 0.6},
	"binarylight":           {"Smart home device", 0.5},
	"dimmablelight":         {"Smart home device", 0.5},
}

// ssdpOS maps the start of the SERVER header's first token (lower case) to
// an operating system.
var ssdpOS = []struct{ prefix, os string }{
	{"linux", "Linux"},
	{"microsoft-windows", "Windows"},
	{"windows", "Windows"},
	{"darwin", "macOS"},
	{"mac os x", "macOS"},
	{"freebsd", "FreeBSD"},
}

func (ssdpIdentifier) Identify(o observation.Observation) []Claim {
	if o.Source != observation.PassiveSSDP {
		return nil
	}
	var out []Claim
	nt := o.Meta["nt"]
	if parts := strings.Split(strings.ToLower(nt), ":"); len(parts) >= 4 && parts[0] == "urn" && parts[2] == "device" {
		if d, ok := ssdpDeviceTypes[parts[3]]; ok {
			out = append(out, claim(FieldDeviceType, d.deviceType, d.confidence, "nt", nt))
		}
	}
	server := o.Meta["server"]
	first, _, _ := strings.Cut(strings.ToLower(server), "/")
	for _, s := range ssdpOS {
		if strings.HasPrefix(first, s.prefix) {
			out = append(out, claim(FieldOS, s.os, 0.5, "server", server))
			break
		}
	}
	return out
}

// wsdIdentifier reads a WS-Discovery announcement: the types it lists
// (ONVIF's NetworkVideoTransmitter, a printer's PrintDeviceType, Windows'
// Computer) and the hardware an ONVIF device names in its scopes.
type wsdIdentifier struct{}

func (wsdIdentifier) Name() string { return "wsd" }

// wsdTypes maps a type's local name to a device type, most specific first.
var wsdTypes = []struct {
	typ, deviceType string
	confidence      float64
}{
	{"NetworkVideoTransmitter", "Camera", 0.7},
	{"PrintDeviceType", "Printer", 0.7},
	{"ScanDeviceType", "Scanner", 0.7},
	{"Computer", "Computer", 0.4}, // pub:Computer: Windows, and Samba's wsdd
}

// onvifCameraTypes are ONVIF type scopes of a camera.
var onvifCameraTypes = []string{"Network_Video_Transmitter", "NetworkVideoTransmitter", "video_encoder"}

func (wsdIdentifier) Identify(o observation.Observation) []Claim {
	if o.Source != observation.PassiveWSD {
		return nil
	}
	var out []Claim
	types := strings.Split(o.Meta["types"], ",")
	onvif := strings.Split(o.Meta["onvif_types"], ",")
	camera := slices.ContainsFunc(onvifCameraTypes, func(t string) bool { return slices.Contains(onvif, t) })
	for _, t := range wsdTypes {
		if slices.Contains(types, t.typ) || t.deviceType == "Camera" && camera {
			out = append(out, claim(FieldDeviceType, t.deviceType, t.confidence, "types", o.Meta["types"], "onvif_types", o.Meta["onvif_types"]))
			break
		}
	}
	if hw := o.Meta["onvif_hardware"]; hw != "" {
		out = append(out, claim(FieldModel, hw, 0.7, "onvif_hardware", hw))
	}
	return out
}
