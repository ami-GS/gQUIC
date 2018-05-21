package quiclatest

import "github.com/ami-GS/gQUIC/latest/qtype"

type StreamManager struct {
	streamMap map[uint64]Stream
	sess      *Session
}

func NewStreamManager(sess *Session) *StreamManager {
	return &StreamManager{
		streamMap: make(map[uint64]Stream),
		sess:      sess,
	}
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

func (s *StreamManager) GetOrNewSendStream(streamID qtype.StreamID, sess *Session) (*SendStream, error) {
	sidVal := streamID.GetValue()

	stream, ok := s.streamMap[sidVal]
	if ok {
		st, ok := stream.(SendStream)
		if !ok {
			// TODO: what error?
			return nil, nil
		}
		return &st, nil
	}
	st := newSendStream(streamID, sess)
	s.streamMap[sidVal] = st
	return st, nil
}

func (s *StreamManager) GetOrNewSendRecvStream(streamID qtype.StreamID, sess *Session) (*SendRecvStream, error) {
	sidVal := streamID.GetValue()

	stream, ok := s.streamMap[sidVal]
	if ok {
		st, ok := stream.(SendRecvStream)
		if !ok {
			// TODO: what error?
			return nil, nil
		}
		return &st, nil
	}
	st := newSendRecvStream(streamID, sess)
	s.streamMap[sidVal] = st
	return st, nil
}
func (s *StreamManager) handleStreamFrame(frame *StreamFrame) error {
	stream, err := s.GetOrNewRecvStream(frame.StreamID, s.sess)
	if err != nil {
		return err
	}
	return stream.handleStreamFrame(frame)
}
func (s *StreamManager) handleStreamBlockedFrame(frame *StreamBlockedFrame) error {
	stream, err := s.GetOrNewRecvStream(frame.StreamID, s.sess)
	if err != nil {
		return err
	}
	return stream.handleStreamBlockedFrame(frame)
}
func (s *StreamManager) handleRstStreamFrame(frame *RstStreamFrame) error {
	stream, err := s.GetOrNewRecvStream(frame.StreamID, s.sess)
	if err != nil {
		return err
	}
	return stream.handleRstStreamFrame(frame)

}
func (s *StreamManager) handleStopSendingFrame(frame *StopSendingFrame) error {
	// TODO: This MUST not crenate New Stream
	stream, err := s.GetOrNewSendStream(frame.StreamID, s.sess)
	if err != nil {
		return err
	}
	return stream.handleStopSendingFrame(frame)
}
func (s *StreamManager) handleMaxStreamDataFrame(frame *MaxStreamDataFrame) error {
	stream, err := s.GetOrNewSendStream(frame.StreamID, s.sess)
	if err != nil {
		return err
	}
	return stream.handleMaxStreamDataFrame(frame)
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
	// application data can be buffered at "Ready" state
	SendBuffer []byte
}

func newSendStream(streamID qtype.StreamID, sess *Session) *SendStream {
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

func (s *SendStream) sendFrame(f Frame) (err error) {
	if s.State == qtype.StreamDataRecvd || s.State == qtype.StreamResetRecvd {
		// MUST NOT send any frame in the states above
		return nil
	}
	switch frame := f.(type) {
	case StreamFrame:
		if s.State == qtype.StreamResetSent {
			// MUST NOT send any frame in the states above
			return nil
		}
		err = s.sendStreamFrame(&frame)
	case StreamBlockedFrame:
		if s.State == qtype.StreamResetSent {
			// MUST NOT send any frame in the states above
			return nil
		}
		err = s.sendStreamBlockedFrame(&frame)
	case RstStreamFrame:
		err = s.sendRstStreamFrame(&frame)
	default:
		// TODO: error
		return nil
	}
	return err
}

func (s *SendStream) sendStreamFrame(f *StreamFrame) error {
	if s.State == qtype.StreamReady {
		s.State = qtype.StreamSend
	} else if s.State == qtype.StreamSend && f.Finish {
		s.State = qtype.StreamDataSent
	}
	return nil
}

func (s *SendStream) sendStreamBlockedFrame(f *StreamBlockedFrame) error {
	if s.State == qtype.StreamReady {
		s.State = qtype.StreamSend
	}
	return nil
}

func (s *SendStream) sendRstStreamFrame(f *RstStreamFrame) error {
	s.State = qtype.StreamResetSent
	//TODO: ResetRecvd after Ack
	return nil
}

// SendStream handle MaxStreamDataFrame  for flow control
func (s *SendStream) handleMaxStreamDataFrame(f *MaxStreamDataFrame) error {
	if s.State == qtype.StreamDataSent {
		// ignore after being "Sent" state
		return nil
	}
	return nil
}

// SendStream handle StopSending for receiving abondon request
func (s *SendStream) handleStopSendingFrame(f *StopSendingFrame) error {
	if s.State == qtype.StreamReady {
		// TODO: connection error of type PROTOCOL_VIOLATION
		return nil
	}
	// respond by RstStreamFrame
	//s.sendRstStreamFrame(NewRstStreamFrame(f.StreamID, 0, 0))
	return nil
}

// AckFrame comes via connection level handling
func (s *SendStream) handleAckFrame(f *AckFrame) error {
	if s.State == qtype.StreamDataSent {
		// TODO: process all stream data are acked then,
		s.State = qtype.StreamDataRecvd
	} else if s.State == qtype.StreamResetSent {
		s.State = qtype.StreamResetRecvd
	}
	return nil
}

func (s *SendStream) ackedAllStreamData() {
	s.State = qtype.StreamDataRecvd
}

type RecvStream struct {
	*BaseStream
	ReorderBuffer map[uint64][]byte
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

// returns data, is_reset
func (s *RecvStream) ReadData() ([]byte, bool) {
	// TODO: blocked until all data received and reordered?
	//       should be implemented by two channel (dataCh and RstCh)
	if s.State == qtype.StreamResetRecvd {
		s.State = qtype.StreamResetRead
		return nil, true
	}
	s.State = qtype.StreamDataRead
	return nil, false
}

func (s *RecvStream) sendMaxStreamDataFrame(f *MaxStreamDataFrame) error {
	//The receiver only sends MAX_STREAM_DATA in the "Recv" state
	if s.State != qtype.StreamRecv {
		return nil
	}

	return nil
}

func (s *RecvStream) sendStopSendingFrame(f *StopSendingFrame) error {
	// A receiver can send STOP_SENDING in any state where it has not received a
	// RST_STREAM frame; that is states other than "Reset Recvd" or "Reset Read"
	if s.State == qtype.StreamResetRecvd || s.State == qtype.StreamResetRead {
		return nil
	}

	return nil
}

func (s *RecvStream) handleRstStreamFrame(f *RstStreamFrame) error {
	if s.State == qtype.StreamDataRecvd {
		// Optional
		s.State = qtype.StreamResetRecvd
	} else if s.State == qtype.StreamRecv || s.State == qtype.StreamSizeKnown {
		s.State = qtype.StreamResetRecvd
	}
	// TODO: discard data received?
	return nil
}

func (s *RecvStream) handleStreamFrame(f *StreamFrame) error {
	if s.State == qtype.StreamDataRecvd {
		// ignore after receiving all data
		return nil
	}

	if f.Finish {
		s.State = qtype.StreamSizeKnown
	}
	//s.ReorderBuffer f.Data

	// do something
	s.State = qtype.StreamDataRecvd
	return nil
}

func (s *RecvStream) handleStreamBlockedFrame(f *StreamBlockedFrame) error {
	if s.State == qtype.StreamDataRecvd {
		// ignore after receiving all data
		return nil
	}
	return nil
}

type SendRecvStream struct {
	*BaseStream
}

func newSendRecvStream(streamID qtype.StreamID, sess *Session) *SendRecvStream {
	return &SendRecvStream{
		BaseStream: &BaseStream{
			ID:    streamID,
			State: qtype.StreamIdle,
			sess:  sess,
		},
	}
}

func (s *SendRecvStream) handleRstStreamFrame(f *RstStreamFrame) error {
	s.State = qtype.StreamClosed
	return nil
}
