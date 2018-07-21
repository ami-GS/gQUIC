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
	finishedStreams    *utils.RingBuffer
	maxStreamIDUni     qtype.StreamID
	nxtSendStreamIDUni qtype.StreamID
	maxStreamIDBidi    qtype.StreamID
	nxtStreamIDBidi    qtype.StreamID
	sess               *Session
	// TODO: name should be considered
	blockedIDs      map[qtype.StreamID]*signedChannel
	blockedIDsMutex *sync.Mutex
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
		maxStreamIDUni:     1,
		nxtSendStreamIDUni: nxtUniID,
		maxStreamIDBidi:    100,
		nxtStreamIDBidi:    nxtBidiID,
		blockedIDs:         make(map[qtype.StreamID]*signedChannel),
		blockedIDsMutex:    new(sync.Mutex),
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

func (s *StreamManager) StartNewSendStream() (Stream, error) {
	targetID := s.nxtSendStreamIDUni
	// TODO: atmic increment?
	s.nxtSendStreamIDUni.Increment()

	if targetID > s.maxStreamIDUni {
		blockedChan := &signedChannel{make(chan struct{}), false}
		s.blockedIDsMutex.Lock()
		s.blockedIDs[targetID] = blockedChan
		s.blockedIDsMutex.Unlock()
		s.sess.sendFrameChan <- NewStreamIDBlockedFrame(targetID)

		<-blockedChan.ch
		delete(s.blockedIDs, targetID)
		close(blockedChan.ch)
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
	sidVal := streamID
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
	s.streamMap[sidVal] = st
	return st, true, nil
}

// called from session.QueueFrame(f)
func (s *StreamManager) QueueFrame(f StreamLevelFrame) error {
	sid := f.GetStreamID()
	var stream Stream
	var err error
	//var isNew bool
	switch f.(type) {
	case *StreamFrame, *RstStreamFrame, *StreamBlockedFrame:
		stream, _, err = s.GetOrNewStream(sid, true)
	case *MaxStreamDataFrame, *StopSendingFrame:
		stream, _, err = s.GetOrNewStream(sid, false)
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

	if frame.StreamID&qtype.UnidirectionalStream == qtype.UnidirectionalStream {
		s.maxStreamIDUni = frame.StreamID
	} else {
		s.maxStreamIDBidi = frame.StreamID
	}

	s.sess.sendFrameChan <- NewMaxStreamIDFrame(frame.StreamID)
	return nil
}
func (s *StreamManager) handleMaxStreamIDFrame(frame *MaxStreamIDFrame) error {
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
	for blockedID, val := range s.blockedIDs {
		if !val.closed && sid >= blockedID {
			val.closed = true
			val.ch <- struct{}{}
		}
	}
	s.blockedIDsMutex.Unlock()
	return nil
}

func (s *StreamManager) resendBlockedFrames(blockedFrames *utils.RingBuffer) error {

	var stream Stream
	var isNew bool
	var err error
	sID := qtype.StreamID(0)
	size := blockedFrames.Size()
	for i := 0; i < size; i++ {
		frame := blockedFrames.Dequeue().(*StreamFrame)
		if sID != frame.GetStreamID() {
			sID = frame.GetStreamID()
			stream, isNew, err = s.GetOrNewStream(sID, true)
			if err != nil {
				return err
			}
			if isNew {
				delete(s.streamMap, sID)
				return nil
			}
		}
		// TODO: stream might be nil
		err := stream.(*SendStream).QueueFrame(frame)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *StreamManager) Read() ([]byte, error) {
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
