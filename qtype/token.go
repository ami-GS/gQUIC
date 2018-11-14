package qtype

type TokenInfo struct {
	Addr  string // ipv4 for now
	Iface string
	Raw   []byte //token
}
