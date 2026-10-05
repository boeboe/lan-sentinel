package platform

// New returns the backends: rtnetlink neighbour and interface monitoring;
// AF_PACKET capture (phase 2) and probe transmission (phase 4) report
// ErrNotImplemented until they land.
func New() Backends {
	return Backends{
		Capturer:    pendingCapturer{pending{backend: "afpacket", phase: 2}},
		Neighbors:   &netlinkNeighbors{},
		Interfaces:  netlinkInterfaces{},
		Transmitter: pendingTransmitter{pending{backend: "afpacket", phase: 4}},
	}
}
