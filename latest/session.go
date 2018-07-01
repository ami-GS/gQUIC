package quiclatest

import (
	"bytes"
	"container/heap"
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
	RetryPacketNum  qtype.PacketNumber

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

	ackPacketQueue *utils.HeapUint64
	UnAckedPacket  map[qtype.PacketNumber]Packet
	mapMutex       *sync.Mutex

	server *Server

	PathChallengeData [8]byte
}

func NewSession(conn *Connection, dstConnID, srcConnID qtype.ConnectionID, isClient bool) *Session {
	h := &utils.HeapUint64{}
	heap.Init(h)
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
		ackPacketQueue:   h,
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
	return stream.(*SendStream).Write(data)
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
		// must come from only client, this method do ack by himself
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

	heap.Push(s.ackPacketQueue, uint64(p.GetPacketNumber()))
	// TODO: need to send ASAP, but how? need to pack acked packet in one frame as much as possible.
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
			err = s.handlePathChallengeFrame(f)
		case *PathResponseFrame:
			err = s.handlePathResponseFrame(f)
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
	} else {
		s.server.DeleteSessionFromMap(s.DestConnID)
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
		s.flowContoller.maybeUpdateMaxDataLimit(f.Data)
	case *PingFrame:
	case *BlockedFrame:
	case *NewConnectionIDFrame:
	case *AckFrame:
	case *PathChallengeFrame:
		s.PathChallengeData = f.Data
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
	if s.flowContoller.maybeUpdateMaxDataLimit(frame.Data) {
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
		for acked := largest; acked >= largest-block.Block; acked -= qtype.PacketNumberIncreaseSize {
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

func (s *Session) handlePathChallengeFrame(frame *PathChallengeFrame) error {
	// TODO: send path response with same data as received PathChallengeFrame
	return nil
}

func (s *Session) handlePathResponseFrame(frame *PathResponseFrame) error {
	if !bytes.Equal(frame.Data[:], s.PathChallengeData[:]) {
		return qtype.UnsolicitedPathResponse
	}
	return nil
}

func (s *Session) handleInitialPacket(p *InitialPacket) error {
	// WIP
	if p.GetPayloadLen() < InitialPacketMinimumPayloadSize {
		return qtype.ProtocolViolation
	}

	if s.RetryPacketNum != 0 {
		s.mapMutex.Lock()
		delete(s.UnAckedPacket, s.RetryPacketNum)
		s.mapMutex.Unlock()
		s.RetryPacketNum = 0
		return nil
	}

	var originalDestID qtype.ConnectionID
	s.DestConnID, originalDestID = p.GetHeader().GetConnectionIDPair()
	if len(originalDestID) < 8 {
		// If the client has not previously received a Retry packet from the server, it populates
		// the Destination Connection ID field with a randomly selected value.
		// This MUST be at least 8 octets in length.
		return qtype.ProtocolViolation
	}

	// The server includes a connection ID of its choice in the Source Connection ID field.
	s.SrcConnID, _ = qtype.NewConnectionID(nil)
	s.server.ChangeConnectionID(originalDestID, s.SrcConnID)

	// send Retry Packet if server wishes to perform a stateless retry
	// It MUST include a STREAM frame on stream 0 with offset 0 containing the server's cryptographic stateless retry material.
	sFrame := NewStreamFrame(0, 0, true, true, false, []byte("server's cryptographic stateless retry material"))
	// It MUST also include an ACK frame to acknowledge the client's Initial packet.
	aFrame := NewAckFrame(qtype.QuicInt(p.GetPacketNumber()), 0, []AckBlock{AckBlock{0, 0}})
	packet := NewRetryPacket(s.versionDecided, s.DestConnID, s.SrcConnID, p.GetPacketNumber(), []Frame{sFrame, aFrame})

	// Next InitialPacket stands for ack implicitely
	s.mapMutex.Lock()
	s.UnAckedPacket[packet.GetPacketNumber()] = packet
	s.mapMutex.Unlock()
	s.RetryPacketNum = packet.GetPacketNumber()
	s.sendPacketChan <- packet
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
