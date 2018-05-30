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

func (s *StreamManager) GetOrNewRecvStream(streamID *qtype.StreamID, sess *Session) (*RecvStream, bool, error) {
	sidVal := streamID.GetValue()
	if sidVal&qtype.UnidirectionalStream != qtype.UnidirectionalStream {
		// error, uni directional should be 0x2 or 0x3
		return nil, false, nil
	}

	stream, ok := s.streamMap[sidVal]
	if ok {
		st, ok := stream.(*RecvStream)
		if !ok {
			// TODO: what error?
			return nil, false, nil
		}
		return st, false, nil
	}
	// check whether ID is larger than MAX_STREAM_ID
	err := s.IsValidID(streamID)
	if err != nil {
		return nil, false, err
	}
	st := newRecvStream(streamID, sess)
	s.streamMap[sidVal] = st
	return st, true, nil
}

func (s *StreamManager) GetOrNewSendStream(streamID *qtype.StreamID, sess *Session) (*SendStream, bool, error) {
	sidVal := streamID.GetValue()
	if sidVal&qtype.UnidirectionalStream != qtype.UnidirectionalStream {
		// error, uni directional should be 0x2 or 0x3
		return nil, false, nil
	}

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

func (s *StreamManager) GetOrNewSendRecvStream(streamID *qtype.StreamID, sess *Session) (*SendRecvStream, bool, error) {
	sidVal := streamID.GetValue()
	if sidVal&qtype.UnidirectionalStream != qtype.UnidirectionalStream {
		// error, bi directional should be 0x0 or 0x1
		return nil, false, nil
	}

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

func (s *StreamManager) handleFrame(f Frame) error {
	var err error
	var stream Stream
	switch frame := f.(type) {
	case MaxStreamIDFrame:
		stream, err = s.handleMaxStreamIDFrame(&frame)
	case StreamIDBlockedFrame:
		stream, err = s.handleStreamIDBlockedFrame(&frame)
	case StreamFrame:
		stream, err = s.handleStreamFrame(&frame)
		if err != nil {
			return err
		}
		stream.UpdateStreamOffsetReceived(frame.Offset.GetValue())
	case RstStreamFrame:
		stream, err = s.handleRstStreamFrame(&frame)
	case MaxStreamDataFrame:
		stream, err = s.handleMaxStreamDataFrame(&frame)
		return err
	case StreamBlockedFrame:
		stream, err = s.handleStreamBlockedFrame(&frame)
	case StopSendingFrame:
		stream, err = s.handleStopSendingFrame(&frame)
	default:
		// error, but impossible to reach here
		return nil
	}
	if stream.IsTerminated() {
		stream.UpdateConnectionByteReceived()
	}
	return err
}

func (s *StreamManager) handleStreamFrame(frame *StreamFrame) (Stream, error) {
	stream, _, err := s.GetOrNewRecvStream(&frame.StreamID, s.sess)
	if err != nil {
		return nil, err
	}
	return stream, stream.handleStreamFrame(frame)
}
func (s *StreamManager) handleStreamBlockedFrame(frame *StreamBlockedFrame) (Stream, error) {
	stream, _, err := s.GetOrNewRecvStream(&frame.StreamID, s.sess)
	if err != nil {
		return nil, err
	}
	return stream, stream.handleStreamBlockedFrame(frame)
}
func (s *StreamManager) handleStreamIDBlockedFrame(frame *StreamIDBlockedFrame) (Stream, error) {
	// should be from sender stream which needs new ID, but could not open due to limit
	s.sess.sendFrameChan <- NewMaxStreamIDFrame(frame.StreamID.GetValue() + 1)
	return nil, nil
}
func (s *StreamManager) handleRstStreamFrame(frame *RstStreamFrame) (Stream, error) {
	stream, _, err := s.GetOrNewRecvStream(&frame.StreamID, s.sess)
	if err != nil {
		return nil, err
	}
	return stream, stream.handleRstStreamFrame(frame)
}
func (s *StreamManager) handleMaxStreamIDFrame(frame *MaxStreamIDFrame) (Stream, error) {
	sid := frame.StreamID.GetValue()

	if sid&qtype.UnidirectionalStream == qtype.UnidirectionalStream {
		// unidirectional
		if sid < s.maxStreamIDUni.GetValue() {
			// ignored
			return nil, nil
		}
		s.maxStreamIDUni = frame.StreamID
	} else {
		//bidirectional
		if sid < s.maxStreamIDBidi.GetValue() {
			// ignored
			return nil, nil
		}
		s.maxStreamIDBidi = frame.StreamID
	}
	return nil, nil
}

func (s *StreamManager) handleStopSendingFrame(frame *StopSendingFrame) (Stream, error) {
	stream, isNew, err := s.GetOrNewSendStream(&frame.StreamID, s.sess)
	if err != nil {
		return nil, err
	}
	// Receiving a STOP_SENDING frame for a send stream that is "Ready" or
	// non-existent MUST be treated as a connection error of type
	// PROTOCOL_VIOLATION.
	if isNew {
		sid := frame.StreamID.GetValue()
		delete(s.streamMap, sid)
		return nil, qtype.ProtocolViolation
	}
	return stream, stream.handleStopSendingFrame(frame)
}
func (s *StreamManager) handleMaxStreamDataFrame(frame *MaxStreamDataFrame) (Stream, error) {
	stream, isNew, err := s.GetOrNewSendStream(&frame.StreamID, s.sess)
	if err != nil {
		return nil, err
	}
	// An endpoint that receives a MAX_STREAM_DATA frame for a send-only
	// stream it has not opened MUST terminate the connection with error
	// PROTOCOL_VIOLATION.
	if isNew {
		sid := frame.StreamID.GetValue()
		delete(s.streamMap, sid)
		return nil, qtype.ProtocolViolation
	}
	return stream, stream.handleMaxStreamDataFrame(frame)
}
