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

func (self *Transport) Send(p Packet) (err error) {
	wire, err := p.GetWire()
	if err != nil {
		return err
	}
	id := p.GetConnectionID()
	conn, ok := self.Conns[id]
	if ok {
		_, err = conn.Write(wire)
	} else {
		return CONNECTION_NOT_FOUND
	}
	return err
}

func (self *Transport) Recv() (err error) {
	return nil
}
