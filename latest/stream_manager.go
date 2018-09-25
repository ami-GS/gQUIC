package quiclatest

import (
	"sync"

	"github.com/ami-GS/gQUIC/latest/qtype"
	"github.com/ami-GS/gQUIC/latest/utils"
)

type signedChannel struct {
	ch     chan struct{}
	closed bool
}

type StreamManager struct {
	streamMap map[qtype.StreamID]Stream
	// would be RcvStream or SendRcvStream
	finishedStreams     *utils.RingBuffer
	maxStreamIDUni      qtype.StreamID
	maxStreamIDUniMutex *sync.Mutex
	nxtSendStreamIDUni  qtype.StreamID
	// TODO: should be replaced by atomic add
	nxtSendStreamIDUniMutex *sync.Mutex

	maxStreamIDBidi qtype.StreamID
	nxtStreamIDBidi qtype.StreamID
	sess            *Session
	// TODO: name should be considered
	blockedIDs             map[qtype.StreamID]*signedChannel
	blockedIDsMutex        *sync.Mutex
	handleMaxStreamIDMutex *sync.Mutex

	newUniStreamMutex  *sync.Mutex
	newBidiStreamMutex *sync.Mutex
	resendMutex        *sync.Mutex

	waitReadingChs *utils.RingBuffer
}

func NewStreamManager(sess *Session) *StreamManager {
	var nxtUniID, nxtBidiID qtype.StreamID
	if sess.isClient {
		nxtUniID = 2
		nxtBidiID = 0
	} else {
		nxtUniID = 3
		nxtBidiID = 1
	}

	return &StreamManager{
		streamMap:       make(map[qtype.StreamID]Stream),
		sess:            sess,
		finishedStreams: utils.NewRingBuffer(20),
		// may be set after handshake, or MAX_STREAM_ID frame
		maxStreamIDUni:          1,
		maxStreamIDUniMutex:     new(sync.Mutex),
		nxtSendStreamIDUni:      nxtUniID,
		nxtSendStreamIDUniMutex: new(sync.Mutex),
		maxStreamIDBidi:         100,
		nxtStreamIDBidi:         nxtBidiID,
		blockedIDs:              make(map[qtype.StreamID]*signedChannel),
		blockedIDsMutex:         new(sync.Mutex),
		handleMaxStreamIDMutex:  new(sync.Mutex),
		newUniStreamMutex:       new(sync.Mutex),
		newBidiStreamMutex:      new(sync.Mutex),
		resendMutex:             new(sync.Mutex),
		// TODO: should be big enough and be able to configurable
		waitReadingChs: utils.NewRingBuffer(30),
	}
}

func (s *StreamManager) IsValidID(streamID qtype.StreamID) error {
	if streamID&qtype.UnidirectionalStream == qtype.UnidirectionalStream {
		// unidirectional
		if streamID > s.maxStreamIDUni {
			return qtype.StreamIDError
		}
	} else {
		// bidirectional
		if streamID > s.maxStreamIDBidi {
			return qtype.StreamIDError
		}
	}
	return nil
}

func (s *StreamManager) requestMaxStreamID(targetID qtype.StreamID) {
	blockedChan := &signedChannel{make(chan struct{}), false}
	s.blockedIDsMutex.Lock()
	s.blockedIDs[targetID] = blockedChan
	s.blockedIDsMutex.Unlock()
	s.sess.sendFrameChan <- NewStreamIDBlockedFrame(targetID)
	<-blockedChan.ch
	s.blockedIDsMutex.Lock()
	delete(s.blockedIDs, targetID)
	s.blockedIDsMutex.Unlock()
	close(blockedChan.ch)
}

func (s *StreamManager) StartNewSendStream() (Stream, error) {
	s.nxtSendStreamIDUniMutex.Lock()
	targetID := s.nxtSendStreamIDUni
	// TODO: atmic increment?
	// looks not working well
	s.nxtSendStreamIDUni.Increment()
	s.nxtSendStreamIDUniMutex.Unlock()
	if targetID > s.maxStreamIDUni {
		s.requestMaxStreamID(targetID)
	}

	stream, _, err := s.GetOrNewStream(targetID, true)
	if err != nil {
		return nil, err
	}
	return stream, nil
}

func (s *StreamManager) GetOrNewStream(streamID qtype.StreamID, send bool) (st Stream, isNew bool, err error) {
	if streamID == 0 {
		return s.getOrNewBidiStream(streamID, s.sess)
	}

	if streamID&qtype.UnidirectionalStream == qtype.UnidirectionalStream {
		st, isNew, err = s.getOrNewUniStream(streamID, s.sess, send)
	} else {
		st, isNew, err = s.getOrNewBidiStream(streamID, s.sess)
	}

	if err != nil {
		delete(s.streamMap, streamID)
		return nil, false, err
	}

	if isNew {
		// check whether ID is larger than MAX_STREAM_ID
		err = s.IsValidID(streamID)
		if err != nil {
			delete(s.streamMap, streamID)
			return nil, false, err
		}
	}

	return st, isNew, err
}

func (s *StreamManager) getOrNewUniStream(streamID qtype.StreamID, sess *Session, send bool) (Stream, bool, error) {
	s.newUniStreamMutex.Lock()
	defer s.newUniStreamMutex.Unlock()
	stream, ok := s.streamMap[streamID]
	// get
	if ok {
		if send {
			st, ok := stream.(*SendStream)
			if !ok {
				// TODO: what error?
				return nil, false, nil
			}
			return st, false, nil
		}
		st, ok := stream.(*RecvStream)
		if !ok {
			// TODO: what error?
			return nil, false, nil
		}
		return st, false, nil

	}
	// new
	if send {
		st := newSendStream(streamID, sess)
		s.streamMap[streamID] = st
		return st, true, nil
	}
	st := newRecvStream(streamID, sess)
	s.streamMap[streamID] = st
	return st, true, nil
}

func (s *StreamManager) getOrNewBidiStream(streamID qtype.StreamID, sess *Session) (*SendRecvStream, bool, error) {
	s.newBidiStreamMutex.Lock()
	defer s.newBidiStreamMutex.Unlock()
	stream, ok := s.streamMap[streamID]
	if ok {
		st, ok := stream.(*SendRecvStream)
		if !ok {
			// TODO: what error?
			return nil, false, nil
		}
		return st, false, nil
	}
	st := newSendRecvStream(streamID, sess)
	s.streamMap[streamID] = st
	return st, true, nil
}

// called from session.QueueFrame(f)
func (s *StreamManager) QueueFrame(stream Stream, f StreamLevelFrame) error {
	sid := f.GetStreamID()
	var err error
	//var isNew bool
	switch frame := f.(type) {
	case *StreamFrame:
		if sid != 0 && frame.Finish {
			if s.sess.flowController.SendableByOffset(frame.Offset) == ConnectionBlocked {
				s.sess.streamManager.resendMutex.Lock()
				s.sess.blockedFramesOnConnection.Enqueue(frame)
				s.sess.streamManager.resendMutex.Unlock()
				err = s.sess.QueueFrame(NewBlockedFrame(frame.Offset + s.sess.flowController.bytesSent))
				return err
			}
			s.sess.UpdateConnectionOffsetSent(frame.Offset)
		}
		if stream == nil {
			stream, _, err = s.GetOrNewStream(sid, true)
		}
	case *RstStreamFrame, *StreamBlockedFrame:
		if stream == nil {
			stream, _, err = s.GetOrNewStream(sid, true)
		}
	case *MaxStreamDataFrame, *StopSendingFrame:
		if stream == nil {
			stream, _, err = s.GetOrNewStream(sid, false)
		}
	case *MaxStreamIDFrame:
		// this is special, affect only stream_manager
		//s.sess.sendFrameChan <- f
		return nil
	case *StreamIDBlockedFrame:
		// ??
		//s.sess.sendFrameChan <- f
		return nil
	default:
		// error, but impossible to reach here
		return nil
	}
	if err != nil {
		return err
	}
	err = stream.QueueFrame(f)
	if err != nil {
		return err
	}
	if stream.IsTerminated() {
		stream.UpdateConnectionByteSent()
	}
	return nil
}

func (s *StreamManager) handleFrame(f StreamLevelFrame) error {
	sid := f.GetStreamID()
	protocolViolationFunc := func() error {
		// An endpoint that receives a MAX_STREAM_DATA frame for a send-only
		// stream it has not opened MUST terminate the connection with error
		// PROTOCOL_VIOLATION.
		delete(s.streamMap, sid)
		return qtype.ProtocolViolation
	}

	var stream Stream
	var err error
	var isNew bool
	switch frame := f.(type) {
	case *MaxStreamIDFrame:
		return s.handleMaxStreamIDFrame(frame)
	case *StreamIDBlockedFrame:
		return s.handleStreamIDBlockedFrame(frame)
	case *StreamFrame:
		stream, isNew, err = s.GetOrNewStream(sid, false)
		if err != nil {
			return err
		}
		if sid != 0 && frame.Finish {
			err := s.sess.flowController.ReceivableByOffset(frame.Offset)
			if err != nil {
				return err
			}
		}
		err = stream.handleStreamFrame(frame)
	case *RstStreamFrame:
		stream, _, err = s.GetOrNewStream(sid, false)
		if err != nil {
			return err
		}
		err = stream.handleRstStreamFrame(frame)
	case *StreamBlockedFrame:
		stream, isNew, err = s.GetOrNewStream(sid, false)
		if err != nil {
			return err
		}
		err = stream.handleStreamBlockedFrame(frame)
	case *MaxStreamDataFrame:
		stream, isNew, err = s.GetOrNewStream(sid, true)
		if err != nil {
			return err
		}
		if isNew {
			return protocolViolationFunc()
		}
		err = stream.handleMaxStreamDataFrame(frame)
		return err
	case *StopSendingFrame:
		stream, isNew, err = s.GetOrNewStream(sid, true)
		if err != nil {
			return err
		}
		if isNew {
			return protocolViolationFunc()
		}
		err = stream.handleStopSendingFrame(frame)
	default:
		// error, but impossible to reach here
		return nil
	}

	if err != nil {
		return err
	}

	if stream.IsTerminated() {
		stream.UpdateConnectionByteReceived()
	}
	return err
}

func (s *StreamManager) handleStreamIDBlockedFrame(frame *StreamIDBlockedFrame) error {
	// should be from sender stream which needs new ID, but could not open due to limit
	s.maxStreamIDUniMutex.Lock()
	// TODO: these setter should be sender of MaxStreamID?
	if frame.StreamID&qtype.UnidirectionalStream == qtype.UnidirectionalStream {
		// This if is not in spec, but should be needed for unordered StreamIDBlocked Frame
		if s.maxStreamIDUni < frame.StreamID {
			s.maxStreamIDUni = frame.StreamID
		}
	} else {
		if s.maxStreamIDBidi < frame.StreamID {
			s.maxStreamIDBidi = frame.StreamID
		}
	}
	s.maxStreamIDUniMutex.Unlock()

	s.sess.sendFrameChan <- NewMaxStreamIDFrame(frame.StreamID)
	return nil
}
func (s *StreamManager) handleMaxStreamIDFrame(frame *MaxStreamIDFrame) error {
	s.handleMaxStreamIDMutex.Lock()
	defer s.handleMaxStreamIDMutex.Unlock()
	sid := frame.StreamID
	if sid&qtype.UnidirectionalStream == qtype.UnidirectionalStream {
		// unidirectional
		if sid < s.maxStreamIDUni {
			// ignored
			return nil
		}
		s.maxStreamIDUni = frame.StreamID
	} else {
		//bidirectional
		if sid < s.maxStreamIDBidi {
			// ignored
			return nil
		}
		s.maxStreamIDBidi = frame.StreamID
	}

	s.blockedIDsMutex.Lock()
	defer s.blockedIDsMutex.Unlock()
	for blockedID, val := range s.blockedIDs {
		if !val.closed && sid >= blockedID {
			val.closed = true
			val.ch <- struct{}{}
		}
	}
	return nil
}

func (s *StreamManager) resendBlockedFrames(blockedFrames *utils.RingBuffer) error {
	var stream Stream
	var isNew bool
	var err error
	sID := qtype.StreamID(0)
	s.resendMutex.Lock()
	size := blockedFrames.Size()
	s.resendMutex.Unlock()
	for i := 0; i < size; i++ {
		s.resendMutex.Lock()
		frame := blockedFrames.Dequeue().(*StreamFrame)
		s.resendMutex.Unlock()
		sID = frame.GetStreamID()
		stream, isNew, err = s.GetOrNewStream(sID, true)
		if err != nil {
			return err
		}
		if isNew {
			// error
			delete(s.streamMap, sID)
			panic("New stream creation for resending frame")
		}
		err := s.QueueFrame(stream, frame)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *StreamManager) waitData() {
	waiting := make(chan struct{})
	s.waitReadingChs.Enqueue(&waiting)
	<-waiting
	close(waiting)
}

func (s *StreamManager) Read() ([]byte, error) {
	if s.finishedStreams.Empty() {
		s.waitData()
	}
	stream, ok := s.finishedStreams.Dequeue().(*RecvStream)
	if !ok || stream == nil {
		return nil, nil
	}
	data, isReset := stream.ReadData()
	// TODO: use isReset to notify the stream was reset
	if isReset {
	}
	return data, nil
}

func (s *StreamManager) Write(data []byte) (n int, err error) {
	streamI, err := s.StartNewSendStream()
	stream := streamI.(*SendStream)
	if err != nil {
		return 0, err
	}
	//return stream.(*SendStream).Write(data)
	// 2. loop to make packet which should have bellow or equal to MTUIPv4
READ_LOOP:
	for uint64(stream.largestOffset) < uint64(len(data)) {
		select {
		case <-stream.stopSendingCh:
			break READ_LOOP
		default:
			remainLen := qtype.QuicInt(len(data[stream.largestOffset:]))
			if remainLen > qtype.MaxPayloadSizeIPv4 {
				stream.largestOffset += qtype.MaxPayloadSizeIPv4
				err = s.QueueFrame(stream, NewStreamFrame(stream.ID, qtype.QuicInt(stream.largestOffset),
					true, true, false, data[stream.largestOffset-qtype.MaxPayloadSizeIPv4:stream.largestOffset]))
			} else {
				stream.largestOffset += remainLen
				err = s.QueueFrame(stream, NewStreamFrame(stream.ID, qtype.QuicInt(stream.largestOffset),
					true, true, true, data[stream.largestOffset-remainLen:]))
			}
			if err != nil {
				return 0, err
			}
		}
	}
	return len(data), err
}

func (s *StreamManager) CloseAllStream() error {
	// implicitly close all stream
	wg := &sync.WaitGroup{}
	for _, stream := range s.streamMap {
		wg.Add(1)
		go func(st Stream) {
			st.Close()
			wg.Done()
		}(stream)
	}
	wg.Wait()
	return nil
}
