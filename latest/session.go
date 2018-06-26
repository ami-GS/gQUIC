package quiclatest

import (
	"sync"
	"time"

	"github.com/ami-GS/gQUIC/latest/qtype"
	"github.com/ami-GS/gQUIC/latest/utils"
)

type Session struct {
	*BasePacketHandler

	// tls config
	// connection
	DestConnID    qtype.ConnectionID
	SrcConnID     qtype.ConnectionID
	DoneHandShake bool
	conn          *Connection
	isClient      bool
	// from server/client to here
	recvPacketChan chan Packet
	// channel should have potential issue
	// use priority queue with Frame which has priority?
	// or prepare several channel for priority based channels ?
	sendFrameChan chan Frame
	// high priority channel when wire has over 1000 (MTUIPv4*0.8)
	sendFrameHPChan chan Frame
	sendPacketChan  chan Packet

	blockedFramesOnConnection *utils.RingBuffer

	streamManager *StreamManager

	flowContoller *ConnectionFlowController

	AssembleFrameChan chan struct{}
	WaitFrameTimeout  *time.Ticker

	closeChan chan struct{}

	PingTicker   *time.Ticker
	timePingSent time.Time

	versionDecided qtype.Version

	LastPacketNumber qtype.PacketNumber

	packetHandler PacketHandler

	UnAckedPacket map[qtype.PacketNumber]Packet
	mapMutex      *sync.Mutex
}

func NewSession(conn *Connection, dstConnID, srcConnID qtype.ConnectionID, isClient bool) *Session {
	sess := &Session{
		DestConnID:     dstConnID,
		SrcConnID:      srcConnID,
		conn:           conn,
		isClient:       isClient,
		recvPacketChan: make(chan Packet),
		// channel size should be configured or detect filled
		sendFrameChan:   make(chan Frame, 100),
		sendFrameHPChan: make(chan Frame, 100),
		sendPacketChan:  make(chan Packet, 100),
		closeChan:       make(chan struct{}),
		flowContoller: &ConnectionFlowController{
			baseFlowController: baseFlowController{
				MaxDataLimit: qtype.MaxPayloadSizeIPv4, //TODO: set appropriate
			},
		},
		blockedFramesOnConnection: utils.NewRingBuffer(20),
		// used for send frame ASAP after generate frame
		AssembleFrameChan: make(chan struct{}, 1),
		// TODO: this would be configurable
		WaitFrameTimeout: time.NewTicker(10 * time.Millisecond),
		// TODO: this should be configured by transport parameter
		PingTicker:       time.NewTicker(15 * time.Second),
		versionDecided:   qtype.VersionPlaceholder,
		LastPacketNumber: qtype.InitialPacketNumber(),
		UnAckedPacket:    make(map[qtype.PacketNumber]Packet),
		mapMutex:         new(sync.Mutex),
	}
	sess.streamManager = NewStreamManager(sess)
	return sess

}

func (s *Session) Run() {
	assemble := func() []Frame {
		frames := make([]Frame, 0)
		byteSize := 0
		for {
			select {
			case frame := <-s.sendFrameChan:
				//frames in sendFrameChan is already evaluated by sess.QueueFrame and stream.QueueFrame
				size := frame.GetWireSize()
				if byteSize+size > qtype.MTUIPv4 {
					// TODO: this should be problem
					// big frame would never be sent
					s.sendFrameChan <- frame
					return frames
				}
				// TODO: consider encrypted wire
				frames = append(frames, frame)
				byteSize += size
			default:
				// If sendFrameChan is empty
				return frames
			}
		}
	}

	var err error
	var frames []Frame
RunLOOP:
	for {
		select {
		case <-s.closeChan:
			break RunLOOP
		case <-s.WaitFrameTimeout.C:
			s.AssembleFrameChan <- struct{}{}
		case <-s.AssembleFrameChan:
			frames = assemble()
			if len(frames) == 0 {
				continue
			}
			err = s.SendPacket(NewProtectedPacket(s.versionDecided, false, s.DestConnID, s.SrcConnID, s.LastPacketNumber.Increase(), 0, frames))
		case <-s.PingTicker.C:
			// currently 1 packet per 1 ping
			err = s.SendPacket(NewProtectedPacket(s.versionDecided, false, s.DestConnID, s.SrcConnID, s.LastPacketNumber.Increase(), 0, []Frame{NewPingFrame()}))
		case f := <-s.sendFrameHPChan:
			err = s.SendPacket(NewProtectedPacket(s.versionDecided, false, s.DestConnID, s.SrcConnID, s.LastPacketNumber.Increase(), 0, []Frame{f}))
		case p := <-s.sendPacketChan:
			// TODO: frames must be evaluated to be sent
			// currently assuming all frames in p is valid
			err = s.SendPacket(p)
		}
		if err != nil {
			// error
		}
	}
	s.WaitFrameTimeout.Stop()
}

func (s *Session) Close(f *ConnectionCloseFrame) error {
	if f != nil {
		// f == nil when called by handleConnectinCloseFrame()
		s.QueueFrame(f)
	}
	_ = s.streamManager.CloseAllStream()
	s.closeChan <- struct{}{}
	close(s.closeChan)
	return nil
}

// TODO: want to implement Read(data []byte) (n int, err error)
func (s *Session) Read() (data []byte, err error) {
	data, err = s.streamManager.Read()
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Write() starts new Stream to send data
func (s *Session) Write(data []byte) (n int, err error) {
	// TODO: encrypt data
	stream, err := s.streamManager.StartNewSendStream()
	if err != nil {
		return 0, err
	}

	offset := uint64(0)
	// 2. loop to make packet which should have bellow or equal to MTUIPv4
	for {
		if len(data[offset:]) > qtype.MaxPayloadSizeIPv4 {
			err = stream.QueueFrame(NewStreamFrame(stream.GetID(), qtype.QuicInt(offset)+qtype.MaxPayloadSizeIPv4, true, true, false, data[offset:offset+qtype.MaxPayloadSizeIPv4]))
			offset += qtype.MaxPayloadSizeIPv4
		} else {
			err = stream.QueueFrame(NewStreamFrame(stream.GetID(), qtype.QuicInt(offset+uint64(len(data[offset:]))), true, true, true, data[offset:]))
			break
		}
		if err != nil {
			return 0, err
		}
	}
	return len(data), err
}

func (s *Session) SendPacket(packet Packet) error {
	wire, err := packet.GetWire()
	if err != nil {
		return err
	}

	s.mapMutex.Lock()
	s.UnAckedPacket[packet.GetPacketNumber()] = packet
	s.mapMutex.Unlock()
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

// send ack frame if needed
func (s *Session) maybeAckPacket(p Packet) {
	// Retry and VersionNegotiation packets are acked by next Initial Packet
	if _, ok := p.(*RetryPacket); ok {
		return
	}
	if _, ok := p.(*VersionNegotiationPacket); ok {
		return
	}
	// ack for InitialPacket sent by handleInitialPacket()
	if _, ok := p.(*InitialPacket); ok {
		return
	}

	for i, frame := range p.GetFrames() {
		if frame.GetType() != AckFrameType && frame.GetType() != PaddingFrameType {
			break
		}
		if i == len(p.GetFrames())-1 {
			// MUST NOT generate packets that only contain ACK
			// frames in response to packets which only contain ACK frames.
			return
		}
	}

	// retrieve packet number from priority queue
	// largest
	// currently send ack for one packet,
	// TODO: should assemble multiple packet number in one ack frame
	// simple slice looks fast

	// decide largest from packet slice
	largest := qtype.QuicInt(p.GetPacketNumber())
	// prepare blocks
	size := 1
	block := make([]AckBlock, size)
	block[0] = AckBlock{largest - qtype.QuicInt(p.GetPacketNumber()), 0}
	/*
		for i := 1; i < size; i++ {
			block[i] = AckBlock{largest - qtype.QuicInt(p.GetPacketNumber()), 0}
		}
	*/
	s.sendFrameChan <- NewAckFrame(largest, 0, block)
	s.AssembleFrameChan <- struct{}{}

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
			err = s.handleBlockedFrame(f)
		case *NewConnectionIDFrame:
		case *AckFrame:
			err = s.handleAckFrame(f)
		case *PathChallengeFrame:
		case *PathResponseFrame:

		case StreamLevelFrame:
			err = s.streamManager.handleFrame(f)
		default:
			// error
			//return nil
		}
		if err != nil {
			//return err
		}
	}
	return nil
}

func (s *Session) handleConnectionCloseFrame(frame *ConnectionCloseFrame) error {
	// would be closed from sender side, but for safety
	s.Close(nil)
	if s.isClient {
		// server shares the conn
		s.conn.Close()
	}
	return nil
}

func (s *Session) QueueFrame(frame Frame) error {
	var err error
	switch f := frame.(type) {
	case *PaddingFrame:
	case *ConnectionCloseFrame:
		// send packet quicly after queueing this frame
		defer func() {
			s.AssembleFrameChan <- struct{}{}
			// needs wait until packet is sent, sleep is not good way
			time.Sleep(100 * time.Millisecond)
		}()
	case *ApplicationCloseFrame:
	case *MaxDataFrame:
		//TODO: controller should be prepared for both direction on Connection?
		s.flowContoller.MaxDataLimit = f.Data
	case *PingFrame:
	case *BlockedFrame:
	case *NewConnectionIDFrame:
	case *AckFrame:
	case *PathChallengeFrame:
	case *PathResponseFrame:
	case StreamLevelFrame:
		err = s.streamManager.QueueFrame(f)
		return err
	default:
		// error
		return nil
	}

	s.sendFrameChan <- frame
	return err
}

func (s *Session) handleBlockedFrame(frame *BlockedFrame) error {
	return s.QueueFrame(NewMaxDataFrame(frame.Offset))
}

func (s *Session) handleMaxDataFrame(frame *MaxDataFrame) error {
	if s.flowContoller.MaxDataLimit < frame.Data {
		s.flowContoller.MaxDataLimit = frame.Data
		err := s.streamManager.resendBlockedFrames(s.blockedFramesOnConnection)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) handleAckFrame(frame *AckFrame) error {
	largest := frame.LargestAcked
	for _, block := range frame.AckBlocks {
		if largest < 0 || largest < block.Block {
			return qtype.FrameError | qtype.TransportError(AckFrameType)
		}
		for acked := largest; acked >= largest-block.Block; acked-- {
			// TODO: would accerelate by using slice, not map
			// TODO: should have AckedPackets map for detect duplicate ack (SHOULD NOT be allowed)
			s.mapMutex.Lock()
			delete(s.UnAckedPacket, qtype.PacketNumber(acked))
			s.mapMutex.Unlock()
		}
		largest -= block.Gap + 2
	}

	return nil
}

func (s *Session) handleInitialPacket(p *InitialPacket) error {
	if p.GetPayloadLen() < InitialPacketMinimumPayloadSize {
		return qtype.ProtocolViolation
	}
	// If server want stateless retry, don't need ack for this packet.
	// Next InitialPacket stands for ack implicitely

	srcID, _ := p.GetHeader().GetConnectionIDPair()
	// TODO: no need to be random for destID
	dstID, _ := qtype.NewConnectionID(nil)

	// WIP
	sFrame := NewStreamFrame(0, 0, true, true, false, []byte{0x11, 0x22})
	aFrame := NewAckFrame(2, 3, []AckBlock{AckBlock{32, 0}})

	s.sendPacketChan <- NewRetryPacket(s.versionDecided, srcID, dstID, p.GetHeader().GetPacketNumber(), []Frame{sFrame, aFrame})
	// containing the server's cryptographic stateless retry material
	//frame1 := NewStreamFrame(0, 0, 0, true, true, false, []byte{})

	// ack for client's InitialPacket
	//frame2 := NewAckFrame(lAcked, ackDelay, ackBlockCount uint64, ackBlocks []AckBlock)
	// RetryPacket
	return nil
}

func (h *Session) handleHandshakePacket(p *HandshakePacket) error {
	return nil
}

func (h *Session) handleProtectedPacket(p *ProtectedPacket) error {
	// Protected Packet whould be same in client & server
	if p.RTT == 0 {

	} else if p.RTT == 1 {

	} else {
		// error
	}

	// decrypt payload
	return nil
}
