package platform

// New returns the backends: AF_PACKET capture and rtnetlink neighbour and
// interface monitoring; probe transmission (phase 4) reports
// ErrNotImplemented until it lands.
func New() Backends {
	return Backends{
		Capturer:    afpacketCapturer{},
		Neighbors:   &netlinkNeighbors{},
		Interfaces:  netlinkInterfaces{},
		Transmitter: pendingTransmitter{pending{backend: "afpacket", phase: 4}},
	}
}
