package identify

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/observation"
)

// claims renders an identifier's claims as "field=value conf [evidence]".
func claims(cs []Claim) string {
	out := make([]string, len(cs))
	for i, c := range cs {
		keys := make([]string, 0, len(c.Evidence))
		for k := range c.Evidence {
			keys = append(keys, k+"="+c.Evidence[k])
		}
		sort.Strings(keys)
		out[i] = fmt.Sprintf("%s=%s %.1f [%s]", c.Field, c.Value, c.Confidence, strings.Join(keys, " "))
	}
	return strings.Join(out, "; ")
}

func TestIdentifiers(t *testing.T) {
	mdns := func(meta ...string) observation.Observation {
		o := observation.Observation{Source: observation.PassiveMDNS, Meta: map[string]string{}}
		for i := 0; i+1 < len(meta); i += 2 {
			o.Meta[meta[i]] = meta[i+1]
		}
		return o
	}
	dhcp := func(key, value string) observation.Observation {
		return observation.Observation{Source: observation.PassiveDHCP, Meta: map[string]string{key: value}}
	}
	name := func(typ observation.NameType, n string) observation.Observation {
		return observation.Observation{Source: observation.PassiveMDNS, Hostname: n, NameType: typ}
	}
	lldp := func(caps string) observation.Observation {
		return observation.Observation{Source: observation.PassiveLLDP, Meta: map[string]string{"capabilities": caps, "system_description": "Industrial Ethernet Switch"}}
	}
	tests := []struct {
		name string
		id   Identifier
		o    observation.Observation
		want string
	}{
		{"mdns printer", mdnsIdentifier{}, mdns("services", "_http._tcp,_ipp._tcp,_uscan._tcp"), "device_type=Printer 0.7 [service=_ipp._tcp]"},
		{"mdns google cast", mdnsIdentifier{}, mdns("services", "_googlecast._tcp"), "device_type=Media player 0.6 [service=_googlecast._tcp]"},
		{"mdns avahi workstation", mdnsIdentifier{}, mdns("services", "_workstation._tcp"),
			"device_type=Computer 0.5 [service=_workstation._tcp]; os=Linux 0.5 [service=_workstation._tcp]"},
		{"mdns undistinctive services", mdnsIdentifier{}, mdns("services", "_http._tcp,_ssh._tcp,_smb._tcp,_airplay._tcp"), ""},
		{"mdns apple model", mdnsIdentifier{}, mdns("services", "_device-info._tcp", "txt", "model=MacBookPro18,3;osxvers=23"),
			"model=MacBookPro18,3 0.7 [txt=model=MacBookPro18,3]; device_type=Computer 0.7 [model=MacBookPro18,3]; os=macOS 0.7 [model=MacBookPro18,3]"},
		{"mdns other model", mdnsIdentifier{}, mdns("txt", "model=TS-453D"), "model=TS-453D 0.7 [txt=model=TS-453D]"},
		{"mdns empty model", mdnsIdentifier{}, mdns("txt", "model=;x=1"), ""},
		{"mdns not mdns", mdnsIdentifier{}, observation.Observation{Source: observation.PassiveARP, Meta: map[string]string{"services": "_ipp._tcp"}}, ""},
		{"dhcp windows", dhcpIdentifier{}, dhcp("vendor_class", "MSFT 5.0"), "os=Windows 0.6 [vendor_class=MSFT 5.0]"},
		{"dhcp android", dhcpIdentifier{}, dhcp("vendor_class", "android-dhcp-14"), "os=Android 0.7 [vendor_class=android-dhcp-14]"},
		{"dhcp dhcpcd", dhcpIdentifier{}, dhcp("vendor_class", "dhcpcd-9.4.1:Linux-6.1.21-v8+:aarch64:BCM2835"),
			"os=Linux 0.6 [vendor_class=dhcpcd-9.4.1:Linux-6.1.21-v8+:aarch64:BCM2835]"},
		{"dhcp apple request list", dhcpIdentifier{}, dhcp("parameter_request_list", "1,121,3,6,15,108,114,119,252,95,44,46"),
			"os=iOS/macOS 0.5 [parameter_request_list=1,121,3,6,15,108,114,119,252,95,44,46]"},
		{"dhcp unknown", dhcpIdentifier{}, dhcp("vendor_class", "PXEClient:Arch:00000"), ""},
		{"dhcp a server's reply is not the client's word", dhcpIdentifier{},
			observation.Observation{Source: observation.PassiveDHCPLease, Meta: map[string]string{"vendor_class": "MSFT 5.0"}}, ""},
		{"hostname android", hostnameIdentifier{}, name(observation.NameMDNS, "Android_K4ZG4TMV.local"), "os=Android 0.4 [hostname=Android_K4ZG4TMV.local]"},
		{"hostname macbook", hostnameIdentifier{}, name(observation.NameMDNS, "Boeboe-MacBookPro-Small.local"),
			"device_type=Computer 0.4 [hostname=Boeboe-MacBookPro-Small.local]; os=macOS 0.4 [hostname=Boeboe-MacBookPro-Small.local]"},
		{"hostname windows", hostnameIdentifier{}, name(observation.NameDHCP, "DESKTOP-4F2K9QA"),
			"device_type=Computer 0.4 [hostname=DESKTOP-4F2K9QA]; os=Windows 0.4 [hostname=DESKTOP-4F2K9QA]"},
		{"hostname hp printer", hostnameIdentifier{}, name(observation.NameMDNS, "HPB00CD1B395F4.local"), "device_type=Printer 0.4 [hostname=HPB00CD1B395F4.local]"},
		{"hostname brother printer", hostnameIdentifier{}, name(observation.NameDHCP, "BRW1C1BB5A3B2C4"), "device_type=Printer 0.4 [hostname=BRW1C1BB5A3B2C4]"},
		{"hostname iphone", hostnameIdentifier{}, name(observation.NameDHCP, "Barts-iPhone"),
			"device_type=Smartphone 0.4 [hostname=Barts-iPhone]; os=iOS 0.4 [hostname=Barts-iPhone]"},
		{"hostname nothing", hostnameIdentifier{}, name(observation.NameMDNS, "plc-a.local"), ""},
		{"hostname from a PTR record is not read", hostnameIdentifier{}, name(observation.NameDNSPTR, "DESKTOP-4F2K9QA.plant.example"), ""},
		{"lldp switch", lldpIdentifier{}, lldp("bridge"), "device_type=Switch 0.8 [capabilities=bridge system_description=Industrial Ethernet Switch]"},
		{"lldp router that bridges", lldpIdentifier{}, lldp("bridge,router"), "device_type=Router 0.8 [capabilities=bridge,router system_description=Industrial Ethernet Switch]"},
		{"lldp phone", lldpIdentifier{}, lldp("bridge,telephone"), "device_type=IP phone 0.8 [capabilities=bridge,telephone system_description=Industrial Ethernet Switch]"},
		{"lldp station", lldpIdentifier{}, lldp("station"), ""},
		{"lldp without description", lldpIdentifier{}, observation.Observation{Source: observation.PassiveLLDP, Meta: map[string]string{"capabilities": "wlan_ap"}},
			"device_type=Access point 0.8 [capabilities=wlan_ap]"},
		{"lldp not lldp", lldpIdentifier{}, observation.Observation{Source: observation.PassiveMDNS, Meta: map[string]string{"capabilities": "router"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := claims(tt.id.Identify(tt.o)); got != tt.want {
				t.Errorf("Identify = %q\n         want %q", got, tt.want)
			}
		})
	}
}

func TestIdentifierToggles(t *testing.T) {
	names := func(ids []Identifier) string {
		var n []string
		for _, id := range ids {
			n = append(n, id.Name())
		}
		return strings.Join(n, ",")
	}
	if got := names(Identifiers(config.Defaults().Identity.Identifiers)); got != "mdns,dhcp,hostname,lldp" {
		t.Errorf("default identifiers = %s", got)
	}
	if got := names(Identifiers(config.IdentifierToggles{DHCP: true, LLDP: true})); got != "dhcp,lldp" {
		t.Errorf("enabled identifiers = %s", got)
	}
}
