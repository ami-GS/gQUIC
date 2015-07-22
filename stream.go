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
		Window: NewWindowSize(),
	}
	return
}
