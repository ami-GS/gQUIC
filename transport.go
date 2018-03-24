package quic

import (
	"net"
)

// TODO: should be encrypt at proper timing
type Transport struct {
	//Conn     *tls.Conn
	UDPConn    *net.UDPConn
	RemoteAddr *net.UDPAddr
	CertPath   string
	KeyPath    string
}

func NewTransport(certPath, keyPath string) (*Transport, error) {
	/*
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
		}
		conn, err := tls.Dial("udp4", string(rAddr.IP)+":"+strconv.Itoa(rAddr.Port), config)
		if err != nil {
			return nil, err
		}
		return &Transport{conn, certPath, keyPath}, nil
	*/
	//conn, err := net.ListenUDP("udp", rAddr)
	return &Transport{
		CertPath: certPath,
		KeyPath:  keyPath,
	}, nil
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
	_, err = self.UDPConn.Write(wire)
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
