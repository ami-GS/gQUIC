package quic

import "fmt"

type State byte

const (
	OPEN State = iota
	HALF_CLOSED
	CLOSED
)

func (s State) String() string {
	return []string{
		"OPEN",
		"HALF_CLOSED",
		"CLOSED",
	}[s]
}

type Stream struct {
	*Conn
	ID        uint32
	State     State
	PeerState State
	Window    *Window
}

func NewStream(streamID uint32, conn *Conn) (stream *Stream) {
	stream = &Stream{
		Conn:      conn,
		ID:        streamID,
		State:     OPEN,
		PeerState: OPEN,
		Window:    NewWindow(),
	}
	return
}

func ReadStreamLevelFrame(conn *Conn, f StreamLevelFrame) error {
	id := f.GetStreamID()
	stream, ok := conn.Streams[id]

	switch frame := f.(type) {
	case *StreamFrame:
		if !ok {
			// implecitely created
			stream = conn.GenStream(id)
		}
		stream.ApplyStreamFrame(frame)
	case *WindowUpdateFrame:
		if !ok {
			return QUIC_PACKET_FOR_NONEXISTENT_STREAM
		}
		stream.ApplyWindowUpdateFrame(frame)
	case *BlockedFrame:
		if !ok {
			return QUIC_PACKET_FOR_NONEXISTENT_STREAM
		}
		stream.ApplyBlockedFrame(frame)
	case *RstStreamFrame:
		// Abrupt termination
		if !ok {
			return QUIC_PACKET_FOR_NONEXISTENT_STREAM
		}
		stream.ApplyRstStream(frame)
	}
	return nil
}

func (self *Stream) ApplyStreamFrame(f *StreamFrame) {
	if f.Fin {
		self.PeerState = HALF_CLOSED
		if self.State == HALF_CLOSED {
			self.State = CLOSED
			self.PeerState = CLOSED
		}
	}
	if self.PeerState == HALF_CLOSED || self.PeerState == CLOSED {
		// TODO : emit error
	}
}

func (self *Stream) ApplyBlockedFrame(f *BlockedFrame) {

}

func (self *Stream) ApplyWindowUpdateFrame(f *WindowUpdateFrame) {

}

func (self *Stream) ApplyRstStream(f *RstStreamFrame) {

}

func (self *Stream) SendStreamFrame(f *StreamFrame) {
	if self.State == HALF_CLOSED || self.State == CLOSED {
		// TODO : emit error
		// cannot send
	}
	if f.Fin {
		self.State = HALF_CLOSED
		if self.PeerState == HALF_CLOSED {
			self.State = CLOSED
			self.PeerState = CLOSED
		}
	}
}

func (self *Stream) String() string {
	str := fmt.Sprintf("Stream ID:%d\n\tLocal State: %s\n\tPeer  State: %s",
		self.ID, self.State.String(), self.PeerState.String())
	return str
}
