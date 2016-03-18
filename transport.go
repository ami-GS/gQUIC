package quic

import (
	"net"
)

// TODO: should be encrypt at proper timing
type Transport struct {
	Conn *net.UDPConn
}

func NewTransport(rAddr *net.UDPAddr) (*Transport, error) {
	conn, err := net.DialUDP("udp4", nil, rAddr)
	if err != nil {
		return nil, err
	}
	return &Transport{conn}, nil
}

func (self *Transport) Connect() (err error) {
	return nil
}

func (self *Transport) Send(p Packet) (err error) {
	wire, err := p.GetWire()
	if err != nil {
		return err
	}
	_, err = self.Conn.Write(wire)
	return err
}

func (self *Transport) Recv() (Packet, int, error) {
	wire := make([]byte, MTU) // TODO: need to check
	len, err := self.Conn.Read(wire)
	if err != nil {
		return nil, len, err
	}
	ph, len, err := ParsePacketHeader(wire, false) //
	if err != nil {
		return nil, len, err
	}
	f, ok := PacketParserMap[ph.Type]
	if !ok {
		return nil, len, QUIC_INVALID_PACKET_HEADER
	}
	p, nxt := f(ph, wire[len:])

	return p, len + nxt, nil
}
