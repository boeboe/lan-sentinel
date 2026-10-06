package platform

// New returns the Linux backends: AF_PACKET capture and probe transmission,
// rtnetlink neighbour and interface monitoring, the kernel clock state.
func New() Backends {
	return Backends{
		Capturer:    afpacketCapturer{},
		Neighbors:   &netlinkNeighbors{},
		Interfaces:  netlinkInterfaces{},
		Transmitter: socketTransmitter{},
		Clock:       adjtimexClock{},
	}
}
