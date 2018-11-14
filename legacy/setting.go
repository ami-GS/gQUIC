package quic

var QUIC_VERSION_LIST []uint32 = []uint32{
	uint32('Q'<<24 | '0'<<16 | '3'<<8 | '4'), // version Q034
}

const (
	MTU      = 1500 // temporally using
	MTU_IPv4 = 1370 // TODO: when to negotiate?
	MTU_IPv6 = 1350
)
