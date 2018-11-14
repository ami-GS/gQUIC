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
	ID                  uint32
	State               State
	PeerState           State
	Window              *Window
	FlowControllBlocked bool
}

func NewStream(streamID uint32, conn *Conn) (stream *Stream) {
	stream = &Stream{
		Conn:                conn,
		ID:                  streamID,
		State:               OPEN,
		PeerState:           OPEN,
		Window:              NewWindow(),
		FlowControllBlocked: false,
	}
	return
}

func ReadStreamLevelFrame(conn *Conn, f StreamLevelFrame) (bool, error) {
	id := f.GetStreamID()
	stream, ok := conn.Streams[id]

	switch frame := f.(type) {
	case *StreamFrame:
		if !ok && conn.SentGoAway {
			// TODO: not accept any new stream
			return false, nil
		} else if !ok {
			// implecitely created
			stream = conn.GenStream(id)
		}
		return stream.ApplyStreamFrame(frame)
	case *WindowUpdateFrame:
		if !ok {
			return false, QUIC_PACKET_FOR_NONEXISTENT_STREAM
		}
		if frame.StreamID == 0 {
			// update for connection
		} else {
			return stream.ApplyWindowUpdateFrame(frame)
		}
	case *BlockedFrame:
		if !ok {
			return false, QUIC_PACKET_FOR_NONEXISTENT_STREAM
		}
		if frame.StreamID == 0 {
			// stream blocked for connection
		} else {
			return stream.ApplyBlockedFrame(frame)
		}
	case *RstStreamFrame:
		// Abrupt termination
		if !ok {
			return false, QUIC_PACKET_FOR_NONEXISTENT_STREAM
		}
		return stream.ApplyRstStreamFrame(frame)
	default:
		// error
	}
	return false, nil
}

func (self *Stream) ApplyStreamFrame(f *StreamFrame) (bool, error) {
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
	return false, nil
}

func (self *Stream) ApplyBlockedFrame(f *BlockedFrame) (bool, error) {
	self.FlowControllBlocked = true
	return false, nil
}

func (self *Stream) ApplyWindowUpdateFrame(f *WindowUpdateFrame) (bool, error) {
	return false, nil
}

func (self *Stream) ApplyRstStreamFrame(f *RstStreamFrame) (bool, error) {
	// means abnormal close
	// creator -> receiver : cancel stream
	// receiver -> creator : error or no frame accepted. should close
	self.State = CLOSED
	return false, nil
}

func (self *Stream) SendFrame(f Frame) {
	if self.State == CLOSED || self.State == HALF_CLOSED {
		// TODO : emit error
		// cannot send
	}
	// TODO: would be map[type]func()
	switch frame := f.(type) {
	case *StreamFrame:
		if frame.Fin {
			self.State = HALF_CLOSED
			if self.PeerState == HALF_CLOSED {
				self.State = CLOSED
				self.PeerState = CLOSED
			}
		}
	case *BlockedFrame:
	case *WindowUpdateFrame:
	case *RstStreamFrame:
	}

}

func (self *Stream) String() string {
	str := fmt.Sprintf("Stream ID:%d\n\tLocal State: %s\n\tPeer  State: %s",
		self.ID, self.State.String(), self.PeerState.String())
	return str
}
