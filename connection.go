package quic

import (
	"math/rand"
	"net"
)

type Conn struct {
	*Transport
	Window       *Window
	Streams      map[uint32]*Stream
	ConnectionID uint64
	RemoteAddr   *net.UDPAddr
	SentGoAway   bool
	RecvGoAway   bool
}

func NewConnection(rAddr *net.UDPAddr) (*Conn, error) {
	return &Conn{
		Transport:    nil,
		Window:       NewWindow(),
		Streams:      make(map[uint32]*Stream),
		ConnectionID: 0,
		RemoteAddr:   rAddr,
		SentGoAway:   false,
		RecvGoAway:   false,
	}, nil
}

func (conn *Conn) Dial() error {
	// TODO: apply apropriate path
	t, err := NewTransport("path/to/cert", "path/to/key")
	if err != nil {
		return err
	}
	err = t.Dial(conn.RemoteAddr)
	if err != nil {
		return err
	}
	conn.ConnectionID, _ = conn.NewConnectionID()
	conn.Transport = t
	return nil
}

func (conn *Conn) Close() error {
	return conn.Transport.Close()
}

func (conn *Conn) handShake() error {
	conn.GenStream(1)
	// TODO: send message
	return nil
}

func (conn *Conn) ReadConnectionLevelFrame(f Frame) error {
	switch frame := f.(type) {
	case *AckFrame:
	case *StopWaitingFrame:
		//case *CongestionFeedBackFrame:
	case *PingFrame:
		// Ack the packet containing this frame
	case *ConnectionCloseFrame:
		// close connection -> close streams -> send GoAwayFrame
	case *GoAwayFrame:
		conn.ApplyGoAwayFrame(frame)
		// will not accept any frame on this connection
	}

	return nil
}

func (conn *Conn) GenStream(streamID uint32) *Stream {
	stream := NewStream(streamID, conn)
	conn.Streams[streamID] = stream
	return stream
}

func (conn *Conn) WritePacket(p Packet) error {
	switch packet := p.(type) {
	case *FramePacket:
		for _, f := range packet.Frames {
			switch (*f).(type) {
			case *GoAwayFrame:
				conn.SentGoAway = true
			}
		}
	}

	return conn.Send(p)
}

func (self *Conn) NewConnectionID() (uint64, error) {
	// TODO: here should be uint64 random
	// TODO: check if ID is already used or not
	id := uint64(rand.Int63())
	return id, nil
}

func (conn *Conn) ApplyGoAwayFrame(f *GoAwayFrame) {
	conn.RecvGoAway = true
}
