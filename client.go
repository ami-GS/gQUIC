package quic

import (
	"math/rand"
)

type Client struct {
	Ct                    *Transport
	FinVersionNegotiation bool
}

func (self *Client) FramePacket(frames []*Frame) {}

func (self *Client) PublicResetPacket() {}

func (self *Client) FECPacket() {}

func (self *Client) getConnectionID() (uint64, error) {
	ok := true
	var id uint64
	for trial := 0; ok; trial++ {
		if trial == 5 {
			return 0, FAIL_TO_SET_CONNECTION_ID
		}
		// TODO: here should be uint64 random
		id = uint64(rand.Int63())
		_, ok = self.Ct.Conns[id]
	}
	return id, nil
}
