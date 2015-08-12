package quic

import (
	"net"
)

type Conn struct {
	Socket  *net.Conn
	Window  *Window
	Streams map[uint32]*Stream
}

func NewConnection(socket *net.Conn) (conn *Conn) {
	conn = &Conn{
		Socket:  socket,
		Window:  NewWindow(),
		Streams: make(map[uint32]*Stream),
	}
	return conn
}

func (conn *Conn) NewStream(streamID uint32) {
	conn.Streams[streamID] = NewStream(streamID, conn.Socket)
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
	case *FECPacket:
	case *PublicResetPacket:
		// Abrubt termination
	}
}
