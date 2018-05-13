package quiclatest

import "github.com/ami-GS/gQUIC/latest/qtype"

type StreamManager struct {
	streamMap map[uint64]Stream
	sess      *Session
}

func (s *StreamManager) GetOrNewRecvStream(streamID qtype.StreamID, sess *Session) (*RecvStream, error) {
	sidVal := streamID.GetValue()

	stream, ok := s.streamMap[sidVal]
	if ok {
		st, ok := stream.(RecvStream)
		if !ok {
			// TODO: what error?
			return nil, nil
		}
		return &st, nil
	}
	st := newRecvStream(streamID, sess)
	s.streamMap[sidVal] = st
	return st, nil
}

func (s *StreamManager) GetOrNewSendStream(streamID qtype.StreamID, sess *Session) (stream Stream, err error) {
	sidVal := streamID.GetValue()

	stream, ok := s.streamMap[sidVal]
	if ok {
		if _, ok := stream.(SendStream); !ok {
			// TODO: what error?
			return nil, err
		}
		return stream, nil
	}
	stream = newSendStream(streamID, sess)
	s.streamMap[sidVal] = stream
	return stream, nil
}

func (s *StreamManager) GetOrNewSendRecvStream(streamID qtype.StreamID, sess *Session) (stream Stream, err error) {
	sidVal := streamID.GetValue()

	stream, ok := s.streamMap[sidVal]
	if ok {
		if _, ok := stream.(SendRecvStream); !ok {
			// TODO: what error?
			return nil, err
		}
		return stream, nil
	}
	stream = newSendRecvStream(streamID, sess)
	s.streamMap[sidVal] = stream
	return stream, nil
}
func (s *StreamManager) handleStreamFrame(frame *StreamFrame) error {
	stream, err := s.GetOrNewRecvStream(frame.StreamID, s.sess)
	if err != nil {
		return err
	}
	stream.handleStreamFrame(frame)
	return nil
}
func (s *StreamManager) handleStreamBlockedFrame(frame *StreamBlockedFrame) error {
	stream, err := s.GetOrNewRecvStream(frame.StreamID, s.sess)
	if err != nil {
		return err
	}
	stream.handleStreamBlockedFrame(frame)
	return nil
}
func (s *StreamManager) handleRstStreamFrame(frame *RstStreamFrame) error {
	stream, err := s.GetOrNewRecvStream(frame.StreamID, s.sess)
	if err != nil {
		return err
	}
	stream.handleRstStreamFrame(frame)
	return nil
}
func (s *StreamManager) handleStopSendingFrame(frame *StopSendingFrame) error {
	// TODO: This MUST not create New Stream
	stream, err := s.GetOrNewRecvStream(frame.StreamID, s.sess)
	if err != nil {
		return err
	}
	stream.handleStopSendingFrame(frame)
	return nil
}
func (s *StreamManager) handleMaxStreamDataFrame(frame *MaxStreamDataFrame) error {
	stream, err := s.GetOrNewRecvStream(frame.StreamID, s.sess)
	if err != nil {
		return err
	}
	stream.handleMaxStreamDataFrame(frame)
	return nil
}

type Stream interface {
	GetState() qtype.StreamState
	GetID() qtype.StreamID
}

type BaseStream struct {
	ID    qtype.StreamID
	State qtype.StreamState
	sess  *Session
}

func (s BaseStream) GetState() qtype.StreamState {
	return s.State
}

func (s BaseStream) GetID() qtype.StreamID {
	return s.ID
}

type SendStream struct {
	*BaseStream
	//Window    *Window
}

func newSendStream(streamID qtype.StreamID, sess *Session) Stream {
	return &SendStream{
		BaseStream: &BaseStream{
			ID:    streamID,
			State: qtype.StreamReady,
			sess:  sess,
		},
		// TODO : need to be able to set initial windowsize
		//Window:              NewWindow(conn.Window.initialSize),
		//FlowControllBlocked: false,
	}
}

func (s *SendStream) sendRstStreamFrame() {
	s.State = qtype.StreamResetSent
	//TODO: ResetRecvd after Ack
}

func (s *SendStream) sendFrame(f Frame) {
	switch frame := f.(type) {
	case StreamFrame:
		if s.State == qtype.StreamReady {
			s.State = qtype.StreamSend
		} else if s.State == qtype.StreamSend && frame.Finish {
			s.State = qtype.StreamDataSent
		}
	case StreamBlockedFrame:
		if s.State == qtype.StreamReady {
			s.State = qtype.StreamSend
		}
	default:
		//error
	}
	//s.sess.SendPacket(packet Packet)
}

type RecvStream struct {
	*BaseStream
	//Window    *Window
}

func newRecvStream(streamID qtype.StreamID, sess *Session) *RecvStream {
	return &RecvStream{
		BaseStream: &BaseStream{
			ID:    streamID,
			State: qtype.StreamRecv,
			sess:  sess,
		},
	}
}

func (s *RecvStream) handleRstStreamFrame(f *RstStreamFrame) {
	if s.State == qtype.StreamDataRecvd {
		// TODO: Optional
	} else if s.State == qtype.StreamRecv || s.State == qtype.StreamSizeKnown {
		s.State = qtype.StreamResetRecvd
	}
	// TODO: ResetRead after app read RST
}
func (s *RecvStream) handleStreamFrame(f *StreamFrame) {
	if f.Finish {
		s.State = qtype.StreamSizeKnown
	}
}
func (s *RecvStream) handleStreamBlockedFrame(f *StreamBlockedFrame) {}
func (s *RecvStream) handleMaxStreamDataFrame(f *MaxStreamDataFrame) {}
func (s *RecvStream) handleStopSendingFrame(f *StopSendingFrame) {
	// send RstStream
	//s.sess.SendPacket(packet Packet)
}

type SendRecvStream struct {
	*BaseStream
}

func newSendRecvStream(streamID qtype.StreamID, sess *Session) Stream {
	return &RecvStream{
		BaseStream: &BaseStream{
			ID:    streamID,
			State: qtype.StreamIdle,
			sess:  sess,
		},
	}
}

func (s *SendRecvStream) handleRstStreamFrame(f *RstStreamFrame) {
	s.State = qtype.StreamClosed
}
