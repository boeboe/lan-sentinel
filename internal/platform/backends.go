package platform

// New returns the backends: AF_PACKET capture and transmit, rtnetlink
// neighbour and interface monitoring. They land in phases 1, 2 and 4; until
// then each reports ErrNotImplemented.
func New() Backends {
	return Backends{
		Capturer:    pendingCapturer{pending{backend: "afpacket", phase: 2}},
		Neighbors:   pendingNeighbors{pending{backend: "netlink", phase: 1}},
		Interfaces:  pendingInterfaces{pending{backend: "netlink", phase: 1}},
		Transmitter: pendingTransmitter{pending{backend: "afpacket", phase: 4}},
	}
}
