package quic

import (
	"math/rand"
	"net"
)

type Client struct {
	Conns                 map[uint64]*Conn
	RemoteAddr            *net.UDPAddr
	FinVersionNegotiation bool
}

func NewClient(addPair string) (*Client, error) {
	rAddr, err := net.ResolveUDPAddr("udp4", addPair)
	if err != nil {
		return nil, err
	}
	return &Client{
		Conns:                 make(map[uint64]*Conn),
		RemoteAddr:            rAddr,
		FinVersionNegotiation: false,
	}, nil
}

func (self *Client) Connect() error {
	return nil
}

// Func name should be same as that of http
func (self *Client) Connect(addPair string) error {
	// if connection is stil alive, then skip
	rAddr, err := utils.ParseAddressPair(addPair)
	if err != nil {
		return err
	}
	conn, err := NewConnection(rAddr)
	if err != nil {
		return err
	}
	self.Conn = conn
	err = self.Conn.Dial()
	if err != nil {
		return err
	}
	p := NewFramePacket(self.Conn.ConnectionID, 1)
	p.PacketHeader.PublicFlags |= CONTAIN_QUIC_VERSION
	p.PacketHeader.Versions = QUIC_VERSION_LIST
	if err != nil {
		return err
	}
	return self.Send(p)
}
func (self *Client) FramePacket(frames []*Frame) error {
	// TODO: When is new connectionID created?
	//       and how is packet number decided?
	p := NewFramePacket(0, 0)
	p.Frames = frames
	conn, ok := self.Conns[p.GetConnectionID()]
	if !ok {
		return CONNECTION_NOT_FOUND
	}
	return conn.WritePacket(p)
}

func (self *Client) PublicResetPacket() {}
