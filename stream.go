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

func (stream *Stream) ReadFrame(f Frame) {
	switch frame := f.(type) {
	case *StreamFrame:
		if frame.Fin == true {
			// Normal termination
		}
	case *WindowUpdateFrame:
	case *BlockedFrame:
	case *RstStreamFrame:
		// Abrupt termination
	}
}
