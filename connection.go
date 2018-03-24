package quic

import (
	"math/rand"
	"net"
	"strconv"
	"strings"
)

type Conn struct {
	*Transport
	Window       *Window
	Streams      map[uint32]*Stream
	ConnectionID uint64
	RemoteAddr   *net.UDPAddr
}

func NewConnection(rAddr *net.UDPAddr) (*Conn, error) {
	return &Conn{
		Transport:    nil,
		Window:       NewWindow(),
		Streams:      make(map[uint32]*Stream),
		ConnectionID: 0,
		RemoteAddr:   rAddr,
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

func (self *Conn) NewConnectionID() (uint64, error) {
	// TODO: here should be uint64 random
	// TODO: check if ID is already used or not
	id := uint64(rand.Int63())
	return id, nil
}
