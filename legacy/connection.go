package quic

import (
	"math/rand"
	"net"
	"time"
)

type Conn struct {
	*Transport
	Window           *Window
	Streams          map[uint32]*Stream
	LastGoodStreamID uint32
	ConnectionID     uint64
	RemoteAddr       *net.UDPAddr
	SentGoAway       bool
	RecvGoAway       bool
	TimeSpawn        time.Time
	PacketIdx        uint64
	UnackedPackets   map[uint64]Packet
}

func NewConnection(rAddr *net.UDPAddr) (*Conn, error) {
	return &Conn{
		Transport:        nil,
		Window:           NewWindow(),
		Streams:          make(map[uint32]*Stream),
		LastGoodStreamID: 0,
		ConnectionID:     0,
		RemoteAddr:       rAddr,
		SentGoAway:       false,
		RecvGoAway:       false,
		TimeSpawn:        time.Now(),
		PacketIdx:        1,
		UnackedPackets:   make(map[uint64]Packet),
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

func (conn *Conn) ReadConnectionLevelFrame(f Frame) (bool, error) {
	switch frame := f.(type) {
	case *AckFrame:
		return conn.ApplyAckFrame(frame)
	case *StopWaitingFrame:
		return conn.ApplyStopWaitingFrame(frame)
		//case *CongestionFeedBackFrame:
	case *PingFrame:
		return conn.ApplyPingFrame(frame)
		// Ack the packet containing this frame
	case *ConnectionCloseFrame:
		return conn.ApplyConnectionCloseFrame(frame)
		// close connection -> close streams -> send GoAwayFrame
	case *GoAwayFrame:
		return conn.ApplyGoAwayFrame(frame)
		// will not accept any frame on this connection
	default:
		// error
	}
	return false, nil
}

func (conn *Conn) GenStream(streamID uint32) *Stream {
	stream := NewStream(streamID, conn)
	conn.Streams[streamID] = stream
	conn.LastGoodStreamID = streamID
	return stream
}

func (conn *Conn) IncrementPacketIdx() {
	if conn.PacketIdx >= 0xffffffffffff {
		conn.PacketIdx = 1
		return
	}
	conn.PacketIdx++
}

func (conn *Conn) WritePacket(p Packet, fromServer bool) error {
	defer conn.IncrementPacketIdx()
	switch packet := p.(type) {
	case *FramePacket:
		for _, f := range packet.Frames {
			switch frame := f.(type) {
			case *GoAwayFrame:
				conn.SentGoAway = true
			case *StreamFrame:
				_, ok := conn.Streams[frame.GetStreamID()]
				if !ok && conn.SentGoAway {
					// TODO: error creating new stream for going away connection
					return nil
				}
			case *ConnectionCloseFrame:
				if conn.SentGoAway {
					// TODO: warning if goaway was not sent
					// this means that "abnormally terminated"
				}
				// terminate streams.
				// terminate connection.
			}
		}
	}
	if fromServer {
		return conn.SendTo(p, conn.RemoteAddr)
	}
	conn.UnackedPackets[p.GetHeader().PacketNumber] = p
	return conn.Send(p)
}

func (self *Conn) NewConnectionID() (uint64, error) {
	// TODO: here should be uint64 random
	// TODO: check if ID is already used or not
	id := uint64(rand.Int63())
	return id, nil
}

func (conn *Conn) ApplyAckFrame(f *AckFrame) (bool, error) {
	// TODO: currently packet is acked immediately. Largest Acked was packet ID sent just before
	_, ok := conn.UnackedPackets[f.LargestAcked]
	if ok {
		delete(conn.UnackedPackets, f.LargestAcked)
	} else {
		//panic(no packet sent)
	}
	return true, nil
}

func (conn *Conn) ApplyStopWaitingFrame(f *StopWaitingFrame) (bool, error) {
	return false, nil
}

func (conn *Conn) ApplyConnectionCloseFrame(f *ConnectionCloseFrame) (bool, error) {
	// check streams have been closed
	// if no, abnormally terminated
	if !conn.RecvGoAway /*|| some streams are stil alive */ {
		// TODO: warning, abnomal termination
	}
	// want to close after all receiving process is finished
	//conn.Close()
	return false, nil
}

func (conn *Conn) ApplyPingFrame(f *PingFrame) (bool, error) {
	return false, nil
}
func (conn *Conn) ApplyGoAwayFrame(f *GoAwayFrame) (bool, error) {
	conn.RecvGoAway = true
	return false, nil
}
