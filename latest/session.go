package quiclatest

import (
	"time"

	"github.com/ami-GS/gQUIC/latest/qtype"
)

type Session struct {
	*BasePacketHandler

	// tls config
	// connection
	DestConnID    qtype.ConnectionID
	SrcConnID     qtype.ConnectionID
	DoneHandShake bool
	conn          *Connection
	// from server/client to here
	recvPacketChan chan Packet
	// channel should have potential issue
	// use priority queue with Frame which has priority?
	// or prepare several channel for priority based channels ?
	sendFrameChan  chan Frame
	sendPacketChan chan Packet

	//blockedFrameChan chan Frame
	blockedStreamIDbyConnection chan *qtype.StreamID

	streamManager *StreamManager

	flowContoller *ConnectionFlowController

	AssembleFrameChan chan struct{}
	WaitFrameTimeout  *time.Ticker

	PingTicker   *time.Ticker
	timePingSent time.Time

	versionDecided qtype.Version

	LastPacketNumber qtype.PacketNumber

	packetHandler PacketHandler
}

func NewSession(conn *Connection, dstConnID, srcConnID qtype.ConnectionID) *Session {
	sess := &Session{
		DestConnID:     dstConnID,
		SrcConnID:      srcConnID,
		conn:           conn,
		recvPacketChan: make(chan Packet),
		// channel size should be configured or detect filled
		sendFrameChan:  make(chan Frame, 100),
		sendPacketChan: make(chan Packet, 100),
		flowContoller: &ConnectionFlowController{
			baseFlowController: baseFlowController{
				MaxDataLimit: 1024, //TODO: set appropriately
			},
		},
		// used for send frame ASAP after generate frame
		AssembleFrameChan: make(chan struct{}),
		// TODO: this would be configurable
		WaitFrameTimeout: time.NewTicker(10 * time.Millisecond),
		// TODO: this should be configured by transport parameter
		PingTicker:       time.NewTicker(15 * time.Second),
		versionDecided:   qtype.VersionPlaceholder,
		LastPacketNumber: qtype.InitialPacketNumber(),
	}
	sess.streamManager = NewStreamManager(sess)
	return sess

}

func (s *Session) Run() {
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
				// TODO: consider encrypted wire
				byteSize += size
			default:
				// If sendFrameChan is empty
				return out[:byteSize]
			}
		}
	}

	var err error
	var wire []byte
	for {
		select {
		//case <- s.CloseChan:
		// 1. closing process
		// 2. close
		case <-s.WaitFrameTimeout.C:
			s.AssembleFrameChan <- struct{}{}
		case <-s.AssembleFrameChan:
			wire = assemble()
			// 1. make Packet wire
			if len(wire) == 0 {
				continue
			}
		case <-s.PingTicker.C:
			// currently 1 packet per 1 ping
			err = s.SendPacket(NewProtectedPacket(s.versionDecided, false, s.DestConnID, s.SrcConnID, s.LastPacketNumber.Increase(), 1, []Frame{NewPingFrame()}))
		case p := <-s.sendPacketChan:
			err = s.SendPacket(p)
		}
		if err != nil {
			// error
		}
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
			// would be possible, but need to use Mutex Lock
			s.HandlePacket(p)
		default:
		}
	}
}

func (s *Session) HandlePacket(p Packet) error {
	var err error

	switch packet := p.(type) {
	case *InitialPacket:
		// must come from only client
		err = s.packetHandler.handleInitialPacket(packet)
	case *RetryPacket:
		// must come from only server
		err = s.packetHandler.handleRetryPacket(packet)
	case *VersionNegotiationPacket:
		// must come from only server
		err = s.packetHandler.handleVersionNegotiationPacket(packet)
	case *ProtectedPacket:
		err = s.handleProtectedPacket(packet)
	case *HandshakePacket:
		err = s.packetHandler.handleHandshakePacket(packet)
		// should be 0 or 1 RTT packet
	}
	if err != nil {
		return err
	}

	err = s.HandleFrames(p.GetFrames())
	if err != nil {
		return err
	}
	s.maybeAckPacket(p)
	return nil
}

func (s *Session) maybeAckPacket(p Packet) {
	// Retry and VersionNegotiation packets are acked by next Initial Packet
	if _, ok := p.(RetryPacket); ok {
		return
	}
	if _, ok := p.(VersionNegotiationPacket); ok {
		return
	}

	// retrieve packet number from priority queue
	// largest

}

func (s *Session) HandleFrames(fs []Frame) error {
	var err error
	for _, frame := range fs {
		switch f := frame.(type) {
		case *PaddingFrame:
		case *ConnectionCloseFrame:
			err = s.handleConnectionCloseFrame(f)
		case *ApplicationCloseFrame:
		case *MaxDataFrame:
			err = s.handleMaxDataFrame(f)
		case *PingFrame:
		case *BlockedFrame:
		case *NewConnectionIDFrame:
		case *AckFrame:
			err = s.handleAckFrame(f)
		case *PathChallengeFrame:
		case *PathResponseFrame:
		case *MaxStreamIDFrame, *StreamIDBlockedFrame, *StreamFrame, *RstStreamFrame,
			*MaxStreamDataFrame, *StreamBlockedFrame, *StopSendingFrame:
			err = s.streamManager.handleFrame(f.(StreamLevelFrame))
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
	s.flowContoller.MaxDataLimit = frame.Data.GetValue()

	for sid := range s.blockedStreamIDbyConnection {
		err := s.streamManager.resendBlockedFrames(sid)
		if err != nil {
			return err
		}
	}
	return nil
}
