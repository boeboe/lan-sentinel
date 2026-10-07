package identify

import (
	"regexp"
	"slices"
	"strings"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/observation"
)

// Claim is what an identifier concludes about a host from one observation
// (docs/DATA_MODEL.md §5.7): a field (FieldDeviceType, FieldOS, FieldModel),
// its value, how far the evidence carries it, and what it rests on.
type Claim struct {
	Field      string
	Value      string
	Confidence float64
	Evidence   map[string]string
}

// Identified fields.
const (
	FieldDeviceType = "device_type"
	FieldOS         = "os"
	FieldModel      = "model"
)

// Identifier derives claims from one observation of a host. Identifiers
// are passive and pure: they read evidence already captured, keep no state
// and send nothing. Name is the identifications source.
type Identifier interface {
	Name() string
	Identify(o observation.Observation) []Claim
}

// Identifiers returns the built-in identifiers the configuration enables,
// in a fixed order.
func Identifiers(t config.IdentifierToggles) []Identifier {
	var out []Identifier
	if t.MDNS {
		out = append(out, mdnsIdentifier{})
	}
	if t.DHCP {
		out = append(out, dhcpIdentifier{})
	}
	if t.Hostname {
		out = append(out, hostnameIdentifier{})
	}
	if t.LLDP {
		out = append(out, lldpIdentifier{})
	}
	return out
}

func claim(field, value string, confidence float64, evidence ...string) Claim {
	c := Claim{Field: field, Value: value, Confidence: confidence, Evidence: map[string]string{}}
	for i := 0; i+1 < len(evidence); i += 2 {
		c.Evidence[evidence[i]] = evidence[i+1]
	}
	return c
}

// mdnsIdentifier reads the service types and the _device-info model a
// device announces over mDNS. Only distinctive services count: _http,
// _ssh, _smb or _airplay say little about what a device is.
type mdnsIdentifier struct{}

func (mdnsIdentifier) Name() string { return "mdns" }

// mdnsServices maps a service type to a device type, most specific first.
var mdnsServices = []struct {
	service, deviceType string
	confidence          float64
}{
	{"_ipp._tcp", "Printer", 0.7},
	{"_ipps._tcp", "Printer", 0.7},
	{"_printer._tcp", "Printer", 0.7},
	{"_pdl-datastream._tcp", "Printer", 0.7},
	{"_googlecast._tcp", "Media player", 0.6},
	{"_hap._tcp", "Smart home device", 0.6},
	{"_workstation._tcp", "Computer", 0.5},
}

// appleModels maps the start of an Apple _device-info model to a device
// type and operating system.
var appleModels = []struct{ prefix, deviceType, os string }{
	{"MacBook", "Computer", "macOS"},
	{"Macmini", "Computer", "macOS"},
	{"MacPro", "Computer", "macOS"},
	{"iMac", "Computer", "macOS"},
	{"Mac", "Computer", "macOS"},
	{"iPhone", "Smartphone", "iOS"},
	{"iPad", "Tablet", "iPadOS"},
	{"AppleTV", "Media player", "tvOS"},
	{"AudioAccessory", "Media player", "audioOS"},
}

func (mdnsIdentifier) Identify(o observation.Observation) []Claim {
	if o.Source != observation.PassiveMDNS {
		return nil
	}
	var out []Claim
	services := strings.Split(o.Meta["services"], ",")
	for _, s := range mdnsServices {
		if slices.Contains(services, s.service) {
			out = append(out, claim(FieldDeviceType, s.deviceType, s.confidence, "service", s.service))
			if s.service == "_workstation._tcp" {
				out = append(out, claim(FieldOS, "Linux", 0.5, "service", s.service)) // avahi announces it
			}
			break
		}
	}
	for _, kv := range strings.Split(o.Meta["txt"], ";") {
		model, ok := strings.CutPrefix(kv, "model=")
		if !ok || model == "" {
			continue
		}
		out = append(out, claim(FieldModel, model, 0.7, "txt", kv))
		for _, m := range appleModels {
			if strings.HasPrefix(model, m.prefix) {
				out = append(out, claim(FieldDeviceType, m.deviceType, 0.7, "model", model),
					claim(FieldOS, m.os, 0.7, "model", model))
				break
			}
		}
		break
	}
	return out
}

// dhcpIdentifier reads what a client says about itself in its own DHCP
// messages: the vendor class (option 60) and the parameter request list
// (option 55).
type dhcpIdentifier struct{}

func (dhcpIdentifier) Name() string { return "dhcp" }

// dhcpVendorClasses maps the start of a vendor class to an operating system.
var dhcpVendorClasses = []struct {
	prefix, os string
	confidence float64
}{
	{"MSFT 5.0", "Windows", 0.6},
	{"android-dhcp-", "Android", 0.7},
	{"dhcpcd-", "Linux", 0.6}, // dhcpcd-<version>:<kernel>:...
	{"udhcp", "Linux", 0.5},   // busybox, embedded Linux
}

// dhcpRequestLists maps whole parameter request lists to an operating
// system: the few that are well documented and distinctive.
var dhcpRequestLists = map[string]string{
	"1,121,3,6,15,108,114,119,252,95,44,46": "iOS/macOS", // iOS 15+, macOS 12+
}

func (dhcpIdentifier) Identify(o observation.Observation) []Claim {
	if o.Source != observation.PassiveDHCP {
		return nil
	}
	if vc := o.Meta["vendor_class"]; vc != "" {
		for _, r := range dhcpVendorClasses {
			if strings.HasPrefix(vc, r.prefix) {
				return []Claim{claim(FieldOS, r.os, r.confidence, "vendor_class", vc)}
			}
		}
	}
	if prl := o.Meta["parameter_request_list"]; prl != "" {
		if os, ok := dhcpRequestLists[prl]; ok {
			return []Claim{claim(FieldOS, os, 0.5, "parameter_request_list", prl)}
		}
	}
	return nil
}

// hostnameIdentifier reads the names devices choose for themselves (mDNS,
// DHCP, LLDP). Names are set by people, so it claims little; a DNS PTR
// name is an administrator's, not the device's, and is not read.
type hostnameIdentifier struct{}

func (hostnameIdentifier) Name() string { return "hostname" }

// hostnamePatterns match a lower-case name without ".local".
var hostnamePatterns = []struct {
	re             *regexp.Regexp
	deviceType, os string
}{
	{regexp.MustCompile(`^android[-_]`), "", "Android"},
	{regexp.MustCompile(`iphone`), "Smartphone", "iOS"},
	{regexp.MustCompile(`ipad`), "Tablet", "iPadOS"},
	{regexp.MustCompile(`macbook|imac|mac-?mini`), "Computer", "macOS"},
	{regexp.MustCompile(`^(desktop|laptop)-[0-9a-z]{7}$`), "Computer", "Windows"},
	{regexp.MustCompile(`^raspberrypi`), "Computer", "Linux"},
	{regexp.MustCompile(`^(hp|npi)[0-9a-f]{6}`), "Printer", ""},
	{regexp.MustCompile(`^br[nw][0-9a-f]{12}$`), "Printer", ""}, // Brother
	{regexp.MustCompile(`^epson`), "Printer", ""},
}

func (hostnameIdentifier) Identify(o observation.Observation) []Claim {
	switch o.NameType {
	case observation.NameMDNS, observation.NameDHCP, observation.NameLLDP:
	default:
		return nil
	}
	name := strings.TrimSuffix(strings.ToLower(o.Hostname), ".local")
	for _, p := range hostnamePatterns {
		if !p.re.MatchString(name) {
			continue
		}
		var out []Claim
		if p.deviceType != "" {
			out = append(out, claim(FieldDeviceType, p.deviceType, 0.4, "hostname", o.Hostname))
		}
		if p.os != "" {
			out = append(out, claim(FieldOS, p.os, 0.4, "hostname", o.Hostname))
		}
		return out
	}
	return nil
}

// lldpIdentifier reads the capabilities a device enables in its LLDP
// advertisements: its own statement of what it does on the network.
type lldpIdentifier struct{}

func (lldpIdentifier) Name() string { return "lldp" }

// lldpRoles maps an enabled capability to a device type, most specific
// first: a router that also bridges is a router.
var lldpRoles = []struct{ capability, deviceType string }{
	{"telephone", "IP phone"},
	{"wlan_ap", "Access point"},
	{"router", "Router"},
	{"docsis", "Cable modem"},
	{"bridge", "Switch"},
}

func (lldpIdentifier) Identify(o observation.Observation) []Claim {
	if o.Source != observation.PassiveLLDP {
		return nil
	}
	caps := strings.Split(o.Meta["capabilities"], ",")
	for _, r := range lldpRoles {
		if slices.Contains(caps, r.capability) {
			ev := []string{"capabilities", o.Meta["capabilities"]}
			if d := o.Meta["system_description"]; d != "" {
				ev = append(ev, "system_description", d)
			}
			return []Claim{claim(FieldDeviceType, r.deviceType, 0.8, ev...)}
		}
	}
	return nil
}
