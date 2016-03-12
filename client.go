package quic

type Client struct {
	Ct                    *Transport
	FinVersionNegotiation bool
}

func (self *Client) FramePacket(frames []*Frame) {}

func (self *Client) PublicResetPacket() {}

func (self *Client) FECPacket() {}
