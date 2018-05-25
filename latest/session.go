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

	flowContoller *ConnectionFlowController
}

func NewSession(conn *Connection, dstConnID, srcConnID qtype.ConnectionID) *Session {
	sess := &Session{
		DestConnID:      dstConnID,
		SrcConnID:       srcConnID,
		conn:            conn,
		recvPacketChann: make(chan Packet),

		flowContoller:     &ConnectionFlowController{},
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
	var err error
	for _, frame := range fs {
		switch f := frame.(type) {
		case PaddingFrame:
		case ConnectionCloseFrame:
			err = s.handleConnectionCloseFrame(&f)
		case ApplicationCloseFrame:
		case MaxDataFrame:
			err = s.handleMaxDataFrame(&f)
		case MaxStreamIDFrame:
			err = s.streamManager.handleMaxStreamIDFrame(&f)
		case PingFrame:
		case BlockedFrame:
		case StreamIDBlockedFrame:
			err = s.streamManager.handleStreamIDBlockedFrame(&f)
		case NewConnectionIDFrame:
		case AckFrame:
		case PathChallengeFrame:
		case PathResponseFrame:
		case StreamFrame:
			err = s.streamManager.handleStreamFrame(&f)
		case RstStreamFrame:
			err = s.streamManager.handleRstStreamFrame(&f)
		case MaxStreamDataFrame:
			err = s.streamManager.handleMaxStreamDataFrame(&f)
		case StreamBlockedFrame:
			err = s.streamManager.handleStreamBlockedFrame(&f)
		case StopSendingFrame:
			err = s.streamManager.handleStopSendingFrame(&f)
		default:
			// error
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) handleConnectionCloseFrame(frame *ConnectionCloseFrame) error {
	// implicitely close streams
	// close connection(session)
	//return frame.ErrorCode
	return nil
}

func (s *Session) handleMaxDataFrame(frame *MaxDataFrame) error {
	//s.DataSizeLimit = frame.Data
	return nil
}
