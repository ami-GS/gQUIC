package quic

import (
	"net"
)

// TODO: should be encrypt at proper timing
type Transport struct {
	Conns map[uint64]*net.UDPConn
}

func (self *Transport) Connect() (err error) {
	return nil
}

func (self *Transport) Send() (err error) {
	return nil
}

func (self *Transport) Recv() (err error) {
	return nil
}
