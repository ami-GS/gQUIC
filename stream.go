package quic

type State byte

const (
	OPEN State = iota
	HALF_CLOSED
	CLOSED
)

type Stream struct {
	ID     uint32
	State  State
	Window *Window
}

func NewStream(streamID uint32) (stream *Stream) {
	stream = &Stream{
		ID:     streamID,
		State:  OPEN,
		Window: NewWindow(),
	}
	return
}

func (stream *Stream) ReadFrame(f Frame) {
	switch frame := f.(type) {
	case *StreamFrame:
	case *AckFrame:
	case *WindowUpdateFrame:
	case *BlockedFrame:
	case *RstStreamFrame:

	}
}
