package quic

import (
	"crypto/tls"
	"net"
	"strconv"
)

// TODO: should be encrypt at proper timing
type Transport struct {
	Conn     *tls.Conn
	CertPath string
	KeyPath  string
}

func NewTransport(rAddr *net.UDPAddr, certPath, keyPath string) (*Transport, error) {
	var config *tls.Config = nil
	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		// TODO: others?
		config = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

func (self *Transport) Listen(rAddr *net.UDPAddr) error {
	conn, err := net.ListenUDP("udp", rAddr)
	if err != nil {
		return err
	}
	self.UDPConn = conn
	return nil
}

func (self *Transport) Dial(rAddr *net.UDPAddr) error {
	conn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		return err
	}
	self.UDPConn = conn
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
