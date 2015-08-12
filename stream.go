package quic

import (
	"net"
)

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
	Conn   *net.Conn
}

func NewStream(streamID uint32, socket *net.Conn) (stream *Stream) {
	stream = &Stream{
		ID:     streamID,
		State:  OPEN,
		Window: NewWindow(),
		Conn:   socket,
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
