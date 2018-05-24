package quiclatest

import (
	"container/heap"

	"github.com/ami-GS/gQUIC/latest/qtype"
	"github.com/ami-GS/gQUIC/latest/utils"
)

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
	if sid&0x2 == 0x2 {
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
	if sidVal&0x3 != 0x2 {
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
	if sidVal&0x2 != 0x2 {
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
	if sidVal&0x2 == 0x2 {
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
func (s *StreamManager) handleStreamFrame(frame *StreamFrame) error {
	stream, _, err := s.GetOrNewRecvStream(&frame.StreamID, s.sess)
	if err != nil {
		return err
	}
	return stream.handleStreamFrame(frame)
}
func (s *StreamManager) handleStreamBlockedFrame(frame *StreamBlockedFrame) error {
	stream, _, err := s.GetOrNewRecvStream(&frame.StreamID, s.sess)
	if err != nil {
		return err
	}
	return stream.handleStreamBlockedFrame(frame)
}
func (s *StreamManager) handleRstStreamFrame(frame *RstStreamFrame) error {
	stream, _, err := s.GetOrNewRecvStream(&frame.StreamID, s.sess)
	if err != nil {
		return err
	}
	return stream.handleRstStreamFrame(frame)

}

func (s *StreamManager) handleStopSendingFrame(frame *StopSendingFrame) error {
	stream, isNew, err := s.GetOrNewSendStream(&frame.StreamID, s.sess)
	if err != nil {
		return err
	}
	// Receiving a STOP_SENDING frame for a send stream that is "Ready" or
	// non-existent MUST be treated as a connection error of type
	// PROTOCOL_VIOLATION.
	if isNew {
		sid := frame.StreamID.GetValue()
		delete(s.streamMap, sid)
		return qtype.ProtocolViolation
	}
	return stream.handleStopSendingFrame(frame)
}
func (s *StreamManager) handleMaxStreamDataFrame(frame *MaxStreamDataFrame) error {
	stream, isNew, err := s.GetOrNewSendStream(&frame.StreamID, s.sess)
	if err != nil {
		return err
	}
	// An endpoint that receives a MAX_STREAM_DATA frame for a send-only
	// stream it has not opened MUST terminate the connection with error
	// PROTOCOL_VIOLATION.
	if isNew {
		sid := frame.StreamID.GetValue()
		delete(s.streamMap, sid)
		return qtype.ProtocolViolation
	}
	return stream.handleMaxStreamDataFrame(frame)
}

type Stream interface {
	GetState() qtype.StreamState
	GetID() qtype.StreamID
	IsTerminated() bool
	handleMaxStreamDataFrame(f *MaxStreamDataFrame) error
	handleStopSendingFrame(f *StopSendingFrame) error
	//handleAckFrame(f *AckFrame) error
	handleRstStreamFrame(f *RstStreamFrame) error
	handleStreamFrame(f *StreamFrame) error
	handleStreamBlockedFrame(f *StreamBlockedFrame) error
}

type BaseStream struct {
	ID    qtype.StreamID
	State qtype.StreamState
	sess  *Session

	DataSizeLimit uint64
	DataSizeUsed  uint64
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

func newSendStream(streamID *qtype.StreamID, sess *Session) *SendStream {
	return &SendStream{
		BaseStream: &BaseStream{
			ID:    *streamID,
			State: qtype.StreamReady,
			sess:  sess,
		},
		// TODO : need to be able to set initial windowsize
		//Window:              NewWindow(conn.Window.initialSize),
		//FlowControllBlocked: false,
	}
}

func (s SendStream) IsTerminated() bool {
	return s.State == qtype.StreamDataRecvd || s.State == qtype.StreamResetRecvd
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
		return qtype.ProtocolViolation
	}
	// respond by RstStreamFrame with error code of STOPPING
	//s.sendRstStreamFrame(NewRstStreamFrame(f.StreamID, qtype.Stopping, 0))
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

func (s *SendStream) handleStreamFrame(f *StreamFrame) error {
	return qtype.ProtocolViolation
}

func (s *SendStream) handleRstStreamFrame(f *RstStreamFrame) error {
	return qtype.ProtocolViolation
}

func (s *SendStream) handleStreamBlockedFrame(f *StreamBlockedFrame) error {
	return qtype.ProtocolViolation
}

func (s *SendStream) ackedAllStreamData() {
	s.State = qtype.StreamDataRecvd
}

type RecvStream struct {
	*BaseStream
	ReorderBuffer *utils.Heap
	DataSize      uint64 // will be known after receiving all data
}

func newRecvStream(streamID *qtype.StreamID, sess *Session) *RecvStream {
	h := &utils.Heap{}
	heap.Init(h)
	return &RecvStream{
		BaseStream: &BaseStream{
			ID:    *streamID,
			State: qtype.StreamRecv,
			sess:  sess,
		},
		ReorderBuffer: h,
	}
}

func (s RecvStream) IsTerminated() bool {
	return s.State == qtype.StreamDataRead || s.State == qtype.StreamResetRead
}

// returns data, is_reset
func (s *RecvStream) ReadData() ([]byte, bool) {
	// TODO: blocked until all data received and reordered?
	//       should be implemented by two channel (dataCh and RstCh)
	if s.State == qtype.StreamResetRecvd {
		s.State = qtype.StreamResetRead
		return nil, true
	}

	out := make([]byte, s.DataSize)
	for s.ReorderBuffer.Len() > 0 {
		item := heap.Pop(s.ReorderBuffer).(*utils.Item)
		copy(out[item.Offset:], item.Data)
	}

	s.State = qtype.StreamDataRead
	return out, false
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

/*
// need to check implementation
func (s *RecvStream) handleAckFrame(f *AckFrame) error                     { return nil }
*/
func (s *RecvStream) handleMaxStreamDataFrame(f *MaxStreamDataFrame) error {
	return qtype.ProtocolViolation
}

func (s *RecvStream) handleStopSendingFrame(f *StopSendingFrame) error {
	return qtype.ProtocolViolation
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
	heap.Push(s.ReorderBuffer, &utils.Item{f.Offset.GetValue(), f.Data})

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

func newSendRecvStream(streamID *qtype.StreamID, sess *Session) *SendRecvStream {
	return &SendRecvStream{
		BaseStream: &BaseStream{
			ID:    *streamID,
			State: qtype.StreamIdle,
			sess:  sess,
		},
	}
}

func (s *SendRecvStream) handleRstStreamFrame(f *RstStreamFrame) error {
	s.State = qtype.StreamClosed
	return nil
}
