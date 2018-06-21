package quiclatest

import (
	"sync"

	"github.com/ami-GS/gQUIC/latest/qtype"
	"github.com/ami-GS/gQUIC/latest/utils"
)

type StreamManager struct {
	streamMap map[uint64]Stream
	// would be RcvStream or SendRcvStream
	finishedStreams *utils.RingBuffer
	maxStreamIDUni  qtype.StreamID
	nxtStreamIDUni  qtype.StreamID
	maxStreamIDBidi qtype.StreamID
	nxtStreamIDBidi qtype.StreamID
	sess            *Session
}

func NewStreamManager(sess *Session) *StreamManager {
	uniID, _ := qtype.NewStreamID(8)
	var nxtUniID, nxtBidiID qtype.StreamID
	if sess.isClient {
		nxtUniID, _ = qtype.NewStreamID(2)
		nxtBidiID, _ = qtype.NewStreamID(0)
	} else {
		nxtUniID, _ = qtype.NewStreamID(3)
		nxtBidiID, _ = qtype.NewStreamID(1)
	}

	bidiID, _ := qtype.NewStreamID(2)
	return &StreamManager{
		streamMap:       make(map[uint64]Stream),
		sess:            sess,
		finishedStreams: utils.NewRingBuffer(20),
		// may be set after handshake, or MAX_STREAM_ID frame
		maxStreamIDUni:  uniID,
		nxtStreamIDUni:  nxtUniID,
		maxStreamIDBidi: bidiID,
		nxtStreamIDBidi: nxtBidiID,
	}
}

func (s *StreamManager) IsValidID(streamID *qtype.StreamID) error {
	sid := streamID.GetValue()

	if sid&qtype.UnidirectionalStream == qtype.UnidirectionalStream {
		// unidirectional
		if sid > s.maxStreamIDUni.GetValue() {
			return qtype.StreamIDError
		}
	} else {
		// bidirectional
		if sid > s.maxStreamIDBidi.GetValue() {
			return qtype.StreamIDError
		}
	}
	return nil
}

func (s *StreamManager) StartNewSendStream() (Stream, error) {
	isNew := false
	var err error
	var stream Stream
	for !isNew {
		stream, isNew, err = s.GetOrNewStream(&s.nxtStreamIDUni, true)
		if err != nil {
			return nil, err
		}
		err = s.nxtStreamIDUni.Increment()
		if err != nil {
			return nil, err
		}
	}
	return stream, nil
}

func (s *StreamManager) GetOrNewStream(streamID *qtype.StreamID, send bool) (st Stream, isNew bool, err error) {
	sidVal := streamID.GetValue()

	if sidVal == 0 {
		return s.getOrNewSendRecvStream(streamID, s.sess)
	}

	if sidVal&qtype.UnidirectionalStream == qtype.UnidirectionalStream {
		if send {
			st, isNew, err = s.getOrNewSendStream(streamID, s.sess)
		} else {
			st, isNew, err = s.getOrNewRecvStream(streamID, s.sess)
		}
	} else {
		st, isNew, err = s.getOrNewSendRecvStream(streamID, s.sess)
	}

	if err != nil {
		delete(s.streamMap, sidVal)
		return nil, false, err
	}

	if isNew {
		// check whether ID is larger than MAX_STREAM_ID
		err = s.IsValidID(streamID)
		if err != nil {
			delete(s.streamMap, sidVal)
			return nil, false, err
		}
	}
	return st, isNew, err
}

func (s *StreamManager) getOrNewRecvStream(streamID *qtype.StreamID, sess *Session) (*RecvStream, bool, error) {
	sidVal := streamID.GetValue()
	stream, ok := s.streamMap[sidVal]
	if ok {
		st, ok := stream.(*RecvStream)
		if !ok {
			// TODO: what error?
			return nil, false, nil
		}
		return st, false, nil
	}
	st := newRecvStream(streamID, sess)
	s.streamMap[sidVal] = st
	return st, true, nil
}

func (s *StreamManager) getOrNewSendStream(streamID *qtype.StreamID, sess *Session) (*SendStream, bool, error) {
	sidVal := streamID.GetValue()
	stream, ok := s.streamMap[sidVal]
	if ok {
		st, ok := stream.(*SendStream)
		if !ok {
			// TODO: what error?
			return nil, false, nil
		}
		return st, false, nil
	}
	st := newSendStream(streamID, sess)
	s.streamMap[sidVal] = st
	return st, true, nil
}

func (s *StreamManager) getOrNewSendRecvStream(streamID *qtype.StreamID, sess *Session) (*SendRecvStream, bool, error) {
	sidVal := streamID.GetValue()
	stream, ok := s.streamMap[sidVal]
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
		stream, _, err = s.GetOrNewStream(&sid, true)
	case *MaxStreamDataFrame, *StopSendingFrame:
		stream, _, err = s.GetOrNewStream(&sid, false)
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
		delete(s.streamMap, sid.GetValue())
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
		stream, _, err = s.GetOrNewStream(&sid, false)
		if err != nil {
			return err
		}
		err = stream.handleStreamFrame(frame)
	case *RstStreamFrame:
		stream, _, err = s.GetOrNewStream(&sid, false)
		if err != nil {
			return err
		}
		err = stream.handleRstStreamFrame(frame)
	case *StreamBlockedFrame:
		stream, _, err = s.GetOrNewStream(&sid, false)
		if err != nil {
			return err
		}
		err = stream.handleStreamBlockedFrame(frame)
	case *MaxStreamDataFrame:
		stream, isNew, err = s.GetOrNewStream(&sid, true)
		if err != nil {
			return err
		}
		if isNew {
			return protocolViolationFunc()
		}
		err = stream.handleMaxStreamDataFrame(frame)
		return err
	case *StopSendingFrame:
		stream, isNew, err = s.GetOrNewStream(&sid, true)
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
	s.sess.sendFrameChan <- NewMaxStreamIDFrame(frame.StreamID.GetValue() + 1)
	return nil
}
func (s *StreamManager) handleMaxStreamIDFrame(frame *MaxStreamIDFrame) error {
	sid := frame.StreamID.GetValue()

	if sid&qtype.UnidirectionalStream == qtype.UnidirectionalStream {
		// unidirectional
		if sid < s.maxStreamIDUni.GetValue() {
			// ignored
			return nil
		}
		s.maxStreamIDUni = frame.StreamID
	} else {
		//bidirectional
		if sid < s.maxStreamIDBidi.GetValue() {
			// ignored
			return nil
		}
		s.maxStreamIDBidi = frame.StreamID
	}
	return nil
}

func (s *StreamManager) resendBlockedFrames(blockedFrames *utils.RingBuffer) error {

	var stream Stream
	var isNew bool
	var err error
	sID := (*qtype.StreamID)(nil)
	size := blockedFrames.Size()
	for i := 0; i < size; i++ {
		frame := blockedFrames.Dequeue().(*StreamFrame)
		sIDtmp := frame.GetStreamID()
		if sID != &sIDtmp {
			sID = &sIDtmp
			stream, isNew, err = s.GetOrNewStream(sID, true)
			if err != nil {
				return err
			}
			if isNew {
				delete(s.streamMap, sID.GetValue())
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
	stream, ok := s.finishedStreams.Dequeue().(Stream)
	if !ok || stream == nil {
		return nil, nil
	}
	data, isReset := stream.(*RecvStream).ReadData()
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
