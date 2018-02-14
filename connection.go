package quic

import (
	"net"
)

type Conn struct {
	*Transport
	Window  *Window
	Streams map[uint32]*Stream
}

func NewConnection(rAddr *net.UDPAddr) (*Conn, error) {
	// TODO: apply apropriate path
	t, err := NewTransport(rAddr, "path/to/cert", "path/to/key")
	if err != nil {
		return nil, err
	}
	return &Conn{
		Transport: t,
		Window:    NewWindow(),
		Streams:   make(map[uint32]*Stream),
	}, nil
}

func (conn *Conn) handShake() error {
	conn.NewStream(1)
	// TODO: send message
	return nil
}

func (conn *Conn) NewStream(streamID uint32) {
	conn.Streams[streamID] = NewStream(streamID, conn)
}

func (conn *Conn) WritePacket(p Packet) error {
	return conn.Send(p)
}

func (conn *Conn) ReadPacket(p Packet) {
	switch packet := p.(type) {
	case *VersionNegotiationPacket:
	case *FramePacket:
		for _, f := range packet.Frames {
			switch (*f).(type) {
			case *AckFrame:
			case *StopWaitingFrame:
			//case *CongestionFeedBackFrame:
			case *PingFrame:
				// Ack the packet containing this frame
			case *ConnectionCloseFrame:
				// close connection -> close streams -> send GoAwayFrame
			case *GoAwayFrame:
				// will not accept any frame on this connection
			case *StreamFrame, *WindowUpdateFrame, *BlockedFrame, *RstStreamFrame:
				//conn.Streams[f.StreamID].ReadFrame(f)
			}
		}
	case *PublicResetPacket:
		// Abrubt termination
	}
}
