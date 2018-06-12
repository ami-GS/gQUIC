package quiclatest

import "github.com/ami-GS/gQUIC/latest/qtype"

type StreamManager struct {
	streamMap       map[uint64]Stream
	maxStreamIDUni  qtype.StreamID
	maxStreamIDBidi qtype.StreamID
	sess            *Session
}

func NewStreamManager(sess *Session) *StreamManager {
	uniID, _ := qtype.NewStreamID(8)
	bidiID, _ := qtype.NewStreamID(2)
	return &StreamManager{
		streamMap: make(map[uint64]Stream),
		sess:      sess,

		// may be set after handshake, or MAX_STREAM_ID frame
		maxStreamIDUni:  uniID,
		maxStreamIDBidi: bidiID,
	}
}

func (s *StreamManager) IsValidID(streamID *qtype.StreamID) error {
	sid := streamID.GetValue()
	if sid&qtype.UnidirectionalStream == qtype.UnidirectionalStream {
		// unidirectional
		if streamID.GetValue() > s.maxStreamIDUni.GetValue() {
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

func (s *StreamManager) resendBlockedFrames(sID *qtype.StreamID) error {
	stream, isNew, err := s.GetOrNewStream(sID, true)
	if err != nil {
		return nil
	}
	if isNew {
		delete(s.streamMap, sID.GetValue())
		return nil
	}
	return stream.(*SendStream).resendBlockedFrames()
}
