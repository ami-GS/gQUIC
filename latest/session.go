package quiclatest

import (
	"bytes"
	"container/heap"
	"log"
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

	// A server MAY encode tokens provided with NEW_TOKEN
	// frames and Retry packets differently, and validate the latter more strictly.
	RetryPacketTokenSent string
	// from Token of Retry Packet, MUST not be discarded
	RetryTokenReceived []byte
	// from NEW_TOKEN
	TokenReceived []byte

	blockedFramesOnConnection *utils.RingBuffer

	streamManager *StreamManager

	flowController *ConnectionFlowController

	AssembleFrameChan chan struct{}
	WaitFrameTimeout  *time.Ticker

	closeChan chan struct{}

	pingHelper *PingHelper

	versionDecided qtype.Version

	LastPacketNumber qtype.PacketNumber

	packetHandler PacketHandler

	ackPacketQueue      *utils.MaxHeapUint64
	ackPacketQueueMutex *sync.Mutex
	UnAckedPacket       map[qtype.PacketNumber]Packet
	mapMutex            *sync.Mutex

	server *Server

	PathChallengeData [8]byte
}

func NewSession(conn *Connection, dstConnID, srcConnID qtype.ConnectionID, isClient bool) *Session {
	h := &utils.MaxHeapUint64{}
	heap.Init(h)
	sess := &Session{
		DestConnID:     dstConnID,
		SrcConnID:      srcConnID,
		conn:           conn,
		isClient:       isClient,
		recvPacketChan: make(chan Packet),
		// channel size should be configured or detect filled
		sendFrameChan:             make(chan Frame, 100),
		sendFrameHPChan:           make(chan Frame, 100),
		sendPacketChan:            make(chan Packet, 100),
		closeChan:                 make(chan struct{}),
		flowController:            NewConnectionFlowController(),
		blockedFramesOnConnection: utils.NewRingBuffer(256),
		// used for send frame ASAP after generate frame
		AssembleFrameChan: make(chan struct{}, 1),
		// TODO: this would be configurable
		WaitFrameTimeout: time.NewTicker(10 * time.Millisecond),
		// TODO: this should be configured by transport parameter
		versionDecided:      qtype.VersionPlaceholder,
		LastPacketNumber:    qtype.InitialPacketNumber,
		ackPacketQueue:      h,
		ackPacketQueueMutex: new(sync.Mutex),
		UnAckedPacket:       make(map[qtype.PacketNumber]Packet),
		mapMutex:            new(sync.Mutex),
		pingHelper:          NewPingHelper(15 * time.Second),
	}
	sess.streamManager = NewStreamManager(sess)
	return sess

}

func (s *Session) Run() {
	assemble := func() []Frame {
		frames := make([]Frame, 0)
		byteSize := 0

		ackFrame := s.AssembleAckFrame()
		if ackFrame != nil {
			frames = append(frames, ackFrame)
			byteSize += ackFrame.GetWireSize()
		}

		for {
			select {
			case frame := <-s.sendFrameChan:
				//frames in sendFrameChan is already evaluated by sess.QueueFrame and stream.QueueFrame
				size := frame.GetWireSize()
				if byteSize+size > qtype.MaxPayloadSizeIPv4 {
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
			err = s.SendPacket(NewProtectedPacket0RTT(s.versionDecided, s.DestConnID, s.SrcConnID, s.LastPacketNumber.Increase(), frames))
		case <-s.pingHelper.Ticker.C:
			// currently 1 packet per 1 ping
			err = s.SendPacket(NewProtectedPacket0RTT(s.versionDecided, s.DestConnID, s.SrcConnID, s.LastPacketNumber.Increase(), []Frame{NewPingFrame()}))
		case f := <-s.sendFrameHPChan:
			err = s.SendPacket(NewProtectedPacket0RTT(s.versionDecided, s.DestConnID, s.SrcConnID, s.LastPacketNumber.Increase(), []Frame{f}))
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
		// f == nil when called by handleConnectinCloseFrame() and
		// PacketNumber reaches maximum
		s.QueueFrame(f)
	}
	_ = s.streamManager.CloseAllStream()
	s.closeChan <- struct{}{}
	close(s.closeChan)
	return nil
}

func (s *Session) ping() {
	s.sendFrameHPChan <- NewPingFrame()
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
	return s.streamManager.Write(data)
}

func (s *Session) SetFinishedStream(stream *RecvStream) {
	s.streamManager.finishedStreams.Enqueue(stream)
	if !s.streamManager.waitReadingChs.Empty() {
		ch := s.streamManager.waitReadingChs.Dequeue().(*(chan struct{}))
		*(ch) <- struct{}{}
	}
}

func (s *Session) SendPacket(packet Packet) error {
	wire, err := packet.GetWire()
	if err != nil {
		return err
	}

	s.mapMutex.Lock()
	if coalescingPacket, ok := packet.(CoalescingPacket); ok {
		for _, ps := range coalescingPacket {
			s.UnAckedPacket[ps.GetPacketNumber()] = ps
		}
	} else {
		s.UnAckedPacket[packet.GetPacketNumber()] = packet
	}
	s.mapMutex.Unlock()

	// NOTICE: unreachable as of now
	if uint64(packet.GetPacketNumber()) == qtype.MaxPacketNumber {
		s.Close(nil)
	}

	s.preprocessWrittenPacket(packet)
	if LogLevel >= 1 {
		host := "server"
		if s.isClient {
			host = "client"
		}
		log.Print("\n== ", host, "Send ====================================================================\n", packet, "\n\n")
	}
	return s.conn.Write(wire)
}

func (s *Session) preprocessWrittenPacket(p Packet) {
	for _, frame := range p.GetFrames() {
		switch frame.GetType() {
		case PingFrameType:
			s.pingHelper.storeSendTime(p.GetPacketNumber())
		default:
			//pass
		}
	}
}

func (s *Session) HandlePacket(p Packet) error {
	if LogLevel >= 1 {
		host := "server"
		if s.isClient {
			host = "client"
		}
		log.Print("\n== ", host, "Received ====================================================================\n", p, "\n\n")
	}

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

func (s *Session) AssembleAckFrame() *AckFrame {
	// TODO: set ECN
	s.ackPacketQueueMutex.Lock()
	defer s.ackPacketQueueMutex.Unlock()
	if s.ackPacketQueue.Len() == 0 {
		return nil
	}
	pLargest := qtype.PacketNumber(heap.Pop(s.ackPacketQueue).(uint64))
	ackBlocks := []AckBlock{}
	if s.ackPacketQueue.Len() == 0 {
		return NewAckFrame(qtype.QuicInt(pLargest), 0, []AckBlock{AckBlock{0, 0}}, nil)
	}

	prevpNum := pLargest
	pNum := pLargest
	count := 0
	for s.ackPacketQueue.Len() > 0 {
		pNum := qtype.PacketNumber(heap.Pop(s.ackPacketQueue).(uint64))
		if pNum == prevpNum-qtype.PacketNumberIncreaseSize {
			count++
		} else {
			ackBlocks = append(ackBlocks, AckBlock{qtype.QuicInt(count), qtype.QuicInt(prevpNum - pNum - 2)})
			count = 0
		}
		prevpNum = pNum
	}
	ackBlocks = append(ackBlocks, AckBlock{qtype.QuicInt(count), qtype.QuicInt(prevpNum - pNum - 2)})
	return NewAckFrame(qtype.QuicInt(pLargest), 0, ackBlocks, nil)
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
		fType := frame.GetType()
		if fType&AckFrameTypeMask != AckFrameTypeA && fType != PaddingFrameType {
			break
		}
		if i == len(p.GetFrames())-1 {
			// MUST NOT generate packets that only contain ACK and PADDING
			// frames in response to packets which only contain ACK frames.
			return
		}
	}

	heap.Push(s.ackPacketQueue, uint64(p.GetPacketNumber()))
	// TODO: need to send ASAP, but how? need to pack acked packet in one frame as much as possible.
}

func (s *Session) HandleFrames(fs []Frame) error {
	// TODO: error should be handled appropriately
	for _, oneFrame := range fs {
		go func(frame Frame) {
			var err error
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
				err = s.handleNewConnectionIDFrame(f)
			case *RetireConnectionIDFrame:
				err = s.handleRetireConnectionIDFrame(f)
			case *PathChallengeFrame:
				err = s.handlePathChallengeFrame(f)
			case *PathResponseFrame:
				err = s.handlePathResponseFrame(f)
			case *CryptoFrame:
				err = s.handleCryptoFrame(f)
			case *NewTokenFrame:
				err = s.handleNewTokenFrame(f)
			case StreamLevelFrame:
				err = s.streamManager.handleFrame(f)
			case *AckFrame:
				err = s.handleAckFrame(f)
			default:
				panic("not supported Frame type")
			}
			if err != nil {
				if e, ok := err.(*qtype.TransportError); ok {
					s.sendFrameHPChan <- NewConnectionCloseFrame(frame.GetType(), *e, "")
				} else {
					panic(err)
				}
			}
		}(oneFrame)
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
		s.flowController.maybeUpdateMaxDataLimit(f.Data)
	case *PingFrame:
	case *BlockedFrame:
	case *NewConnectionIDFrame:
	case *AckFrame:
	case *PathChallengeFrame:
		s.PathChallengeData = f.Data
	case *PathResponseFrame:
	case *CryptoFrame:
	case *NewTokenFrame:
	case StreamLevelFrame:
		err = s.streamManager.QueueFrame(nil, f)
		return err
	default:
		// error
		return nil
	}

	s.sendFrameChan <- frame
	return err
}

func (s *Session) UpdateConnectionOffsetSent(offset qtype.QuicInt) {
	s.flowController.updateByteSent(offset)
}

func (s *Session) handleBlockedFrame(frame *BlockedFrame) error {
	return s.QueueFrame(NewMaxDataFrame(frame.Offset))
}

func (s *Session) handleMaxDataFrame(frame *MaxDataFrame) error {
	if s.flowController.maybeUpdateMaxDataLimit(frame.Data) {
		err := s.streamManager.resendBlockedFrames(s.blockedFramesOnConnection)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) handleNewConnectionIDFrame(frame *NewConnectionIDFrame) error {
	panic("NotImplementedError")
	return nil
}

func (s *Session) handleRetireConnectionIDFrame(frame *RetireConnectionIDFrame) error {
	panic("NotImplementedError")
	return nil
}

func (s *Session) handleAckFrame(frame *AckFrame) error {
	//ackedPNs := make([]qtype.PacketNumber, 1+frame.AckBlockCount)
	//idx := 0
	var ackedPNs []qtype.PacketNumber
	largest := frame.LargestAcked
	for _, block := range frame.AckBlocks {
		if largest < 0 || largest < block.Block {
			return qtype.FrameEncodingError
		}
		for acked := largest; acked >= largest-block.Block; acked -= qtype.PacketNumberIncreaseSize {
			//ackedPNs[idx] = qtype.PacketNumber(acked)
			ackedPNs = append(ackedPNs, qtype.PacketNumber(acked))
		}
		largest -= block.Gap + 2
	}

	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()
	for _, pn := range ackedPNs {
		// TODO: not good for performance?
		s.pingHelper.calcPingDuration(pn)
		// TODO: would accerelate by using slice, not map
		// TODO: should have AckedPackets map for detect duplicate ack (SHOULD NOT be allowed)
		delete(s.UnAckedPacket, pn)
	}

	return nil
}

func (s *Session) handlePathChallengeFrame(frame *PathChallengeFrame) error {
	// TODO: send path response with same data as received PathChallengeFrame
	return nil
}

func (s *Session) handlePathResponseFrame(frame *PathResponseFrame) error {
	if !bytes.Equal(frame.Data[:], s.PathChallengeData[:]) {
		return qtype.ProtocolViolation
	}
	return nil
}

func (s *Session) handleCryptoFrame(f *CryptoFrame) error {
	return nil
}
func (s *Session) handleNewTokenFrame(f *NewTokenFrame) error {
	if !s.isClient {
		// This is not written in spec, need to ask
		return qtype.ProtocolViolation
	}

	// If the client has a token received in a NEW_TOKEN frame on a previous
	// connection to what it believes to be the same server, it can include
	// that value in the Token field of its Initial packet.
	// TODO: configurable
	if true {
		s.TokenReceived = f.Token
		// TODO: store token for next connection
	}
	// Tokens obtained in Retry packets MUST NOT be discarded

	return nil
}

func (s *Session) handleInitialPacket(p *InitialPacket) error {
	// TODO: clean up codes
	oneRTTForNow := false
	initialPacketForNow := false
	if lh, ok := p.GetHeader().(*LongHeader); ok && lh.Length < InitialPacketMinimumPayloadSize {
		return qtype.ProtocolViolation
	}
	var originalDestID qtype.ConnectionID
	s.DestConnID, originalDestID = p.GetHeader().GetConnectionIDPair()
	if len(originalDestID) < 8 {
		// If the client has not previously received a Retry packet from the server, it populates
		// the Destination Connection ID field with a randomly selected value.
		// This MUST be at least 8 octets in length.
		return qtype.ProtocolViolation
	}

	if p.TokenLen != 0 {
		if bytes.Equal(p.Token, []byte(s.RetryPacketTokenSent)) {
			return nil
		}
	}

	packetNum := p.GetPacketNumber()
	for _, frame := range p.GetFrames() {
		// TODO: check packet number
		if frame.GetType()&AckFrameTypeMask == AckFrameTypeA && packetNum == 0 {
			if s.isClient {
				packets := []Packet{}
				// TODO: set ECN
				packets = append(packets,
					NewInitialPacket(s.versionDecided, s.DestConnID, s.SrcConnID, nil, 1,
						[]Frame{NewAckFrame(qtype.QuicInt(p.GetPacketNumber()), 0, nil, nil)}),
					NewHandshakePacket(s.versionDecided, s.DestConnID, s.SrcConnID, 0,
						[]Frame{NewCryptoFrame(qtype.QuicInt(len("first cryptographic handshake message (ClientHello)")), []byte("CRYPTO[FIN]")),
							NewAckFrame(qtype.QuicInt(p.GetPacketNumber()), 0, nil, nil),
						}))
				if oneRTTForNow {
					s.sendPacketChan <- NewCoalescingPacket(append(packets, NewProtectedPacket1RTT(false, s.DestConnID, 0,
						[]Frame{NewStreamFrame(0, 0, true, true, true, []byte("1-RTT[0]: STREAM[0, ...]")),
							NewAckFrame(qtype.QuicInt(p.GetPacketNumber()), 0, nil, nil),
						})))
				} else {
					// TODO: unknown offset
					s.sendPacketChan <- NewCoalescingPacket(append(packets,
						NewProtectedPacket0RTT(s.versionDecided, s.DestConnID, s.SrcConnID, 1,
							[]Frame{NewCryptoFrame(0, []byte("0-RTT[1]: CRYPTO[EOED]"))}),
						NewProtectedPacket1RTT(false, s.DestConnID, 2,
							[]Frame{NewStreamFrame(0, 0, true, true, true, []byte("1-RTT[2]: STREAM[0, ...]")),
								NewAckFrame(qtype.QuicInt(p.GetPacketNumber()), 0, nil, nil),
							})))
				}
			} else { // server
				if oneRTTForNow {
					s.sendPacketChan <- NewCoalescingPacket([]Packet{
						NewProtectedPacket1RTT(false, s.DestConnID, 1,
							[]Frame{NewStreamFrame(55, 0, true, true, true, []byte("1-RTT[1]: STREAM[55, ...]")),
								NewAckFrame(qtype.QuicInt(p.GetPacketNumber()), 0, nil, nil)}),
						NewHandshakePacket(s.versionDecided, s.DestConnID, s.SrcConnID, 1,
							[]Frame{NewAckFrame(qtype.QuicInt(p.GetPacketNumber()), 0, nil, nil)})})
				} else {
					s.sendPacketChan <- NewCoalescingPacket([]Packet{
						NewProtectedPacket1RTT(false, s.DestConnID, 1,
							[]Frame{NewStreamFrame(55, 0, true, true, true, []byte("1-RTT[1]: STREAM[55, ...]")),
								NewAckFrame(qtype.QuicInt(p.GetPacketNumber()+1), 0, nil, nil)}),
						NewHandshakePacket(s.versionDecided, s.DestConnID, s.SrcConnID, s.LastPacketNumber,
							[]Frame{NewAckFrame(qtype.QuicInt(p.GetPacketNumber()+2), 0, []AckBlock{AckBlock{qtype.QuicInt(p.GetPacketNumber() + 1), 0}}, nil)}),
					})
				}
			}
			return nil
		}
	}
	if packetNum != 0 {
		return nil
	}

	// The server includes a connection ID of its choice in the Source Connection ID field.
	s.SrcConnID, _ = qtype.NewConnectionID(nil)
	s.server.ChangeConnectionID(originalDestID, s.SrcConnID)

	// TODO: need to check condition
	if initialPacketForNow {
		// initial packet from server or retry packet from server
		// TODO: set ECN
		packets := []Packet{
			NewInitialPacket(s.versionDecided, s.DestConnID, s.SrcConnID, nil, 0,
				[]Frame{NewCryptoFrame(0, []byte("first cryptographic handshake message from server (HelloRetryRequest)")),
					NewAckFrame(qtype.QuicInt(p.GetPacketNumber()), 0, nil, nil)}),
			// TODO: this is stil under investigating
			NewHandshakePacket(s.versionDecided, s.DestConnID, s.SrcConnID, s.LastPacketNumber,
				[]Frame{NewCryptoFrame(qtype.QuicInt(len("first cryptographic handshake message from server (HelloRetryRequest)")), []byte("CRYPTO[EE, CERT, CV, FIN]"))}),
		}
		protectedFrames := []Frame{NewStreamFrame(1, 0, true, true, true, []byte("1-RTT[0]: STREAM[1, ...]"))}
		if oneRTTForNow {
			// 1-RTT handshake
			// TODO: need to know key is used or not
			s.sendPacketChan <- NewCoalescingPacket(append(packets, NewProtectedPacket1RTT(false, s.DestConnID, 0, protectedFrames)))
		} else {
			// 0-RTT handshake
			s.sendPacketChan <- NewCoalescingPacket(append(packets, NewProtectedPacket0RTT(s.versionDecided, s.DestConnID, s.SrcConnID, 0,
				append(protectedFrames, NewAckFrame(qtype.QuicInt(p.GetPacketNumber()), 0, nil, nil)))))

		}
	} else {
		//TODO: should be hash?
		s.RetryPacketTokenSent = "not sure what should be here"
		s.sendPacketChan <- NewRetryPacket(s.versionDecided, s.DestConnID, s.SrcConnID, originalDestID,
			[]byte(s.RetryPacketTokenSent))
	}
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
