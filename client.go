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

func (self *Client) newConnectionID() (uint64, error) {
	ok := true
	var id uint64
	for trial := 0; ok; trial++ {
		if trial == 5 {
			return 0, FAIL_TO_SET_CONNECTION_ID
		}
		// TODO: here should be uint64 random
		id = uint64(rand.Int63())
		_, ok = self.Conns[id]
	}
	return id, nil
}
