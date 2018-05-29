package quiclatest

import (
	"time"

	"github.com/ami-GS/gQUIC/latest/qtype"
)

type Session struct {
	// tls config
	// connection
	DestConnID    qtype.ConnectionID
	SrcConnID     qtype.ConnectionID
	DoneHandShake bool
	conn          *Connection
	// from server/client to here
	recvPacketChan chan Packet
	// to fill sendFrameBuffer till timeout or filled by about MTU?
	sendFrameChan chan Frame

	streamManager *StreamManager

	flowContoller *ConnectionFlowController

	AssembleFrameChan chan struct{}
	WaitFrameTimeout  *time.Ticker
}

func NewSession(conn *Connection, dstConnID, srcConnID qtype.ConnectionID) *Session {
	sess := &Session{
		DestConnID:     dstConnID,
		SrcConnID:      srcConnID,
		conn:           conn,
		recvPacketChan: make(chan Packet),
		// channel size should be configured or detect filled
		sendFrameChan: make(chan Frame, 100),
		flowContoller: &ConnectionFlowController{
			baseFlowController: baseFlowController{
				MaxDataLimit: 1024, //TODO: set appropriately
			},
		},
		// used for send frame ASAP after generate frame
		AssembleFrameChan: make(chan struct{}),
		// TODO: this would be configurable
		WaitFrameTimeout: time.NewTicker(10 * time.Millisecond),
	}
	sess.streamManager = NewStreamManager(sess)
	return sess

}

func (s *Session) AssembleFrameLoop() {
	assemble := func() []byte {
		out := make([]byte, qtype.MTUIPv4)
		byteSize := 0
		for {
			select {
			case frame := <-s.sendFrameChan:
				size := frame.GetWireSize()
				if byteSize+size > qtype.MTUIPv4 {
					// TODO: this should be problem
					// big frame would never be sent
					s.sendFrameChan <- frame
					return out[:byteSize]
				}
				copy(out[byteSize:], frame.GetWire())
				byteSize += size
			default:
				// If sendFrameChan is empty
				return out[:byteSize]
			}
		}
	}

	var wire []byte
	for {
		select {
		case <-s.AssembleFrameChan:
			wire = assemble()
		case <-s.WaitFrameTimeout.C:
			wire = assemble()
		}
		if len(wire) == 0 {
			continue
		}
		// 1. make Packet
		// 2. send Packet
	}
	s.WaitFrameTimeout.Stop()
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
		case p := <-s.recvPacketChan:
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
		case PingFrame:
		case BlockedFrame:
		case NewConnectionIDFrame:
		case AckFrame:
		case PathChallengeFrame:
		case PathResponseFrame:
		case MaxStreamIDFrame, StreamIDBlockedFrame, StreamFrame, RstStreamFrame,
			MaxStreamDataFrame, StreamBlockedFrame, StopSendingFrame:
			err = s.streamManager.handleFrame(frame)
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
