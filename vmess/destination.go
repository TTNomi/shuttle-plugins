package vmess

// Destination represents a network destination including address and protocol (tcp / udp).
type Destination struct {
	Address Address
	Port    Port
	Network string
}

// NetAddr returns the network address in this Destination in string form.
func (d Destination) NetAddr() string {
	return d.Address.String() + ":" + d.Port.String()
}

// String returns the strings form of this Destination.
func (d Destination) String() string {
	return d.Network + ":" + d.NetAddr()
}

// IsValid returns true if this Destination is valid.
func (d Destination) IsValid() bool {
	return d.Network == "tcp" || d.Network == "udp"
}
