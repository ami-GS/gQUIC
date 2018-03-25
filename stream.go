package quic

type State byte

const (
	OPEN State = iota
	HALF_CLOSED
	CLOSED
)

type Stream struct {
	*Conn
	ID     uint32
	State  State
	Window *Window
}

func NewStream(streamID uint32, conn *Conn) (stream *Stream) {
	stream = &Stream{
		Conn:   conn,
		ID:     streamID,
		State:  OPEN,
		Window: NewWindow(),
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
		if frame.Fin == true {
			// Normal termination
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

}

func (self *Stream) ApplyBlockedFrame(f *BlockedFrame) {

}

func (self *Stream) ApplyWindowUpdateFrame(f *WindowUpdateFrame) {

}

func (self *Stream) ApplyRstStream(f *RstStreamFrame) {

}
