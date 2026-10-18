package identify

import (
	"testing"

	"lan-sentinel/internal/observation"
)

func TestDiscoveryIdentifiers(t *testing.T) {
	obs := func(src observation.Source, meta ...string) observation.Observation {
		o := observation.Observation{Source: src, Meta: map[string]string{}}
		for i := 0; i+1 < len(meta); i += 2 {
			o.Meta[meta[i]] = meta[i+1]
		}
		return o
	}
	nb := func(meta ...string) observation.Observation { return obs(observation.PassiveNetBIOS, meta...) }
	tests := []struct {
		name string
		id   Identifier
		o    observation.Observation
		want string
	}{
		{"netbios workgroup", netbiosIdentifier{}, nb("netbios", "registration", "workgroup", "PLANT"),
			"workgroup=PLANT 0.7 [netbios=registration] replace"},
		{"netbios domain controllers group", netbiosIdentifier{}, nb("netbios", "registration", "workgroup", "PLANT", "role", "domain_controller"),
			"workgroup=PLANT 0.7 [netbios=registration] replace; device_type=Domain controller 0.6 [netbios=registration role=domain_controller]"},
		{"netbios windows workstation", netbiosIdentifier{}, nb("netbios", "host_announcement", "os_version", "6.1", "server_type", "workstation,server,nt"),
			"device_type=Computer 0.4 [server_type=workstation,server,nt]; os=Windows 0.6 [server_type=workstation,server,nt]; " +
				"os_version=6.1 0.6 [os_version=6.1 server_type=workstation,server,nt] replace"},
		{"netbios windows server", netbiosIdentifier{}, nb("netbios", "host_announcement", "server_type", "workstation,server,nt,server_nt"),
			"device_type=Server 0.5 [server_type=workstation,server,nt,server_nt]; os=Windows 0.6 [server_type=workstation,server,nt,server_nt]"},
		{"netbios domain controller announcement", netbiosIdentifier{}, nb("netbios", "host_announcement", "server_type", "workstation,domain_controller,nt,server_nt"),
			"device_type=Domain controller 0.6 [server_type=workstation,domain_controller,nt,server_nt]; os=Windows 0.6 [server_type=workstation,domain_controller,nt,server_nt]"},
		{"netbios samba: no windows claims", netbiosIdentifier{}, nb("netbios", "host_announcement", "os_version", "6.1", "server_type", "workstation,server,unix,nt"), ""},
		{"netbios name only", netbiosIdentifier{}, nb("netbios", "registration"), ""},
		{"netbios not netbios", netbiosIdentifier{}, obs(observation.PassiveMDNS, "workgroup", "PLANT"), ""},

		{"cdp switch", cdpIdentifier{}, obs(observation.PassiveCDP, "capabilities", "switch,igmp", "platform", "cisco IE-4000-8GT4G-E",
			"software", "Cisco IOS Software, Version 15.2(7)E4"),
			"device_type=Switch 0.8 [capabilities=switch,igmp]; model=cisco IE-4000-8GT4G-E 0.8 [platform=cisco IE-4000-8GT4G-E]; " +
				"firmware=Cisco IOS Software, Version 15.2(7)E4 0.8 [software=Cisco IOS Software, Version 15.2(7)E4] replace"},
		{"cdp layer 3 switch is a router", cdpIdentifier{}, obs(observation.PassiveCDP, "capabilities", "router,switch,igmp"),
			"device_type=Router 0.8 [capabilities=router,switch,igmp]"},
		{"cdp phone", cdpIdentifier{}, obs(observation.PassiveCDP, "capabilities", "host,phone"), "device_type=IP phone 0.8 [capabilities=host,phone]"},
		{"cdp host only", cdpIdentifier{}, obs(observation.PassiveCDP, "capabilities", "host"), ""},
		{"cdp not cdp", cdpIdentifier{}, obs(observation.PassiveLLDP, "platform", "x"), ""},

		{"ssdp gateway on linux", ssdpIdentifier{}, obs(observation.PassiveSSDP, "nt", "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
			"server", "Linux/4.14 UPnP/1.0 MiniUPnPd/2.1"),
			"device_type=Router 0.6 [nt=urn:schemas-upnp-org:device:InternetGatewayDevice:1]; os=Linux 0.5 [server=Linux/4.14 UPnP/1.0 MiniUPnPd/2.1]"},
		{"ssdp media renderer on windows", ssdpIdentifier{}, obs(observation.PassiveSSDP, "nt", "urn:schemas-upnp-org:device:MediaRenderer:1",
			"server", "Microsoft-Windows/10.0 UPnP/1.0 UPnP-Device-Host/1.0"),
			"device_type=Media player 0.6 [nt=urn:schemas-upnp-org:device:MediaRenderer:1]; os=Windows 0.5 [server=Microsoft-Windows/10.0 UPnP/1.0 UPnP-Device-Host/1.0]"},
		{"ssdp basic device: no type", ssdpIdentifier{}, obs(observation.PassiveSSDP, "nt", "urn:schemas-upnp-org:device:Basic:1", "server", "IpBridge/1.21.0"), ""},
		{"ssdp root device", ssdpIdentifier{}, obs(observation.PassiveSSDP, "nt", "upnp:rootdevice", "server", "Linux/3.10, UPnP/1.0"),
			"os=Linux 0.5 [server=Linux/3.10, UPnP/1.0]"},
		{"ssdp not ssdp", ssdpIdentifier{}, obs(observation.PassiveWSD, "nt", "urn:schemas-upnp-org:device:Printer:1"), ""},

		{"wsd onvif camera", wsdIdentifier{}, obs(observation.PassiveWSD, "types", "NetworkVideoTransmitter,Device", "onvif_hardware", "DS-2CD2143G0-I",
			"onvif_types", "video_encoder,Network_Video_Transmitter"),
			"device_type=Camera 0.7 [onvif_types=video_encoder,Network_Video_Transmitter types=NetworkVideoTransmitter,Device]; " +
				"model=DS-2CD2143G0-I 0.7 [onvif_hardware=DS-2CD2143G0-I]"},
		{"wsd camera by its onvif scope only", wsdIdentifier{}, obs(observation.PassiveWSD, "types", "Device", "onvif_types", "video_encoder"),
			"device_type=Camera 0.7 [onvif_types=video_encoder types=Device]"},
		{"wsd printer", wsdIdentifier{}, obs(observation.PassiveWSD, "types", "Device,PrintDeviceType"),
			"device_type=Printer 0.7 [types=Device,PrintDeviceType]"},
		{"wsd computer", wsdIdentifier{}, obs(observation.PassiveWSD, "types", "Device,Computer"), "device_type=Computer 0.4 [types=Device,Computer]"},
		{"wsd device only", wsdIdentifier{}, obs(observation.PassiveWSD, "types", "Device"), ""},
		{"wsd not wsd", wsdIdentifier{}, obs(observation.PassiveSSDP, "types", "PrintDeviceType"), ""},

		{"hostname from a netbios name", hostnameIdentifier{}, observation.Observation{Source: observation.PassiveNetBIOS,
			Hostname: "DESKTOP-4F2K9QA", NameType: observation.NameNetBIOS},
			"device_type=Computer 0.4 [hostname=DESKTOP-4F2K9QA]; os=Windows 0.4 [hostname=DESKTOP-4F2K9QA]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := claims(tt.id.Identify(tt.o)); got != tt.want {
				t.Errorf("Identify = %q\n         want %q", got, tt.want)
			}
		})
	}
}
