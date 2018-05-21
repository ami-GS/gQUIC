package quiclatest

import "github.com/ami-GS/gQUIC/latest/qtype"

type Session struct {
	// tls config
	// connection
	DestConnID      qtype.ConnectionID
	SrcConnID       qtype.ConnectionID
	DoneHandShake   bool
	conn            *Connection
	recvPacketChann chan Packet
	streamManager   *StreamManager
}

func NewSession(conn *Connection, dstConnID, srcConnID qtype.ConnectionID) *Session {
	sess := &Session{
		DestConnID:      dstConnID,
		SrcConnID:       srcConnID,
		conn:            conn,
		recvPacketChann: make(chan Packet),
	}
	sess.streamManager = NewStreamManager(sess)
	return sess

}

func (s *Session) SendPacket(packet Packet) error {
	wire, err := packet.GetWire()
	if err != nil {
		return err
	}
	return s.conn.Write(wire)
}
func (s *Session) RecvPacketLoop() {
	for {
		select {
		case p := <-s.recvPacketChann:
			// TODO: parallel?
			s.HandlePacket(p)
		default:
		}
	}
}

func (s *Session) HandlePacket(p Packet) {
	switch p.(type) {
	case InitialPacket:
		// must come from only client
		// RetryPacket
	case RetryPacket:
		// must come from only server
		// InitialPacket again

	}

	s.HandleFrames(p.GetFrames())
}

func (s *Session) HandleFrames(fs []Frame) error {
	for _, frame := range fs {
		switch f := frame.(type) {
		case PaddingFrame:
		case ConnectionCloseFrame:
		case ApplicationCloseFrame:
		case MaxDataFrame:
		case MaxStreamIDFrame:
		case PingFrame:
		case BlockedFrame:
		case StreamIDBlockedFrame:
		case NewConnectionIDFrame:
		case AckFrame:
		case PathChallengeFrame:
		case PathResponseFrame:
		case StreamFrame:
			s.streamManager.handleStreamFrame(&f)
		case RstStreamFrame:
			s.streamManager.handleRstStreamFrame(&f)
		case MaxStreamDataFrame:
			s.streamManager.handleMaxStreamDataFrame(&f)
		case StreamBlockedFrame:
			s.streamManager.handleStreamBlockedFrame(&f)
		case StopSendingFrame:
			s.streamManager.handleStopSendingFrame(&f)
		default:
			// error
			return nil
		}
	}
	return nil
}
