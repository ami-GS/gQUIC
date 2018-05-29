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

type Stream interface {
	GetState() qtype.StreamState
	GetID() qtype.StreamID
	IsTerminated() bool
	UpdateConnectionByteSent()
	UpdateConnectionByteReceived()
	UpdateStreamOffsetSent(offset uint64)
	UpdateStreamOffsetReceived(offset uint64)
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

	flowcontroller *StreamFlowController
}

func (s BaseStream) GetState() qtype.StreamState {
	return s.State
}

func (s BaseStream) GetID() qtype.StreamID {
	return s.ID
}

func (s BaseStream) UpdateConnectionByteSent() {
	s.flowcontroller.connFC.updateByteSent(s.flowcontroller.largestSent)
}

func (s BaseStream) UpdateConnectionByteReceived() {
	s.flowcontroller.connFC.updateByteReceived(s.flowcontroller.largestReceived)
}

func (s BaseStream) UpdateStreamOffsetSent(offset uint64) {
	s.flowcontroller.updateLargestSent(offset)
}

func (s BaseStream) UpdateStreamOffsetReceived(offset uint64) {
	s.flowcontroller.updateLargestReceived(offset)
}

type SendStream struct {
	*BaseStream
	// application data can be buffered at "Ready" state
	SendBuffer []byte
	// used for storing frame for blocked frames. can be chan *StreamFrame?
	BlockedFramesChan chan Frame
}

func newSendStream(streamID *qtype.StreamID, sess *Session) *SendStream {
	sid := streamID.GetValue()
	return &SendStream{
		BaseStream: &BaseStream{
			ID:    *streamID,
			State: qtype.StreamReady,
			sess:  sess,
			// TODO: need to check default MAX_STREAM_DATA
			flowcontroller: &StreamFlowController{
				IsStreamZero: sid == 0,
				connFC:       sess.flowContoller,
				baseFlowController: baseFlowController{
					MaxDataLimit: 1024, // TODO: set appropriately
				},
			},
		},
		// TODO: be careful for the size
		BlockedFramesChan: make(chan Frame, 10),
		// TODO : need to be able to set initial windowsize
		//FlowControllBlocked: false,
	}
}

func (s SendStream) IsTerminated() bool {
	return s.State == qtype.StreamDataRecvd || s.State == qtype.StreamResetRecvd
}

func (s *SendStream) resendBlockedFrames() error {
	// TODO: be careful for multithread
	var blockedFrames []Frame
	for frame := range s.BlockedFramesChan {
		blockedFrames = append(blockedFrames, frame)
	}

	for _, frame := range blockedFrames {
		err := s.sendFrame(frame)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SendStream) sendFrame(f Frame) (err error) {
	if s.IsTerminated() {
		// MUST NOT send any frame in the states above
		return nil
	}
	switch frame := f.(type) {
	case StreamFrame:
		if s.State == qtype.StreamResetSent {
			// MUST NOT send Stream frame in the states above
			return nil
		}
		err = s.sendStreamFrame(&frame)
		dataOffset := frame.Offset.GetValue()
		if s.flowcontroller.SendableByOffset(dataOffset, frame.Finish) {
			s.UpdateStreamOffsetSent(dataOffset)
		} else {
			// STREAM_BLOCKED　?
			// queue the frame until MAX_DATA will be sent
			err = s.sendFrame(NewStreamBlockedFrame(s.GetID().GetValue(), dataOffset))
			s.BlockedFramesChan <- frame
			return nil
		}
	case StreamBlockedFrame:
		if s.State == qtype.StreamResetSent {
			// MUST NOT send StreamBlocked frame in the states above
			return nil
		}
		err = s.sendStreamBlockedFrame(&frame)
	case RstStreamFrame:
		err = s.sendRstStreamFrame(&frame)
	default:
		// TODO: error
		return nil
	}

	if s.IsTerminated() {
		s.UpdateConnectionByteSent()
	}

	s.sess.sendFrameChan <- f
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
	s.flowcontroller.MaxDataLimit = f.Data.GetValue()

	// this doesn't send anything for the first MAX_STREAM frame for first setting
	s.resendBlockedFrames()
	return nil
}

// SendStream handle StopSending for receiving abondon request
func (s *SendStream) handleStopSendingFrame(f *StopSendingFrame) error {
	if s.State == qtype.StreamReady {
		return qtype.ProtocolViolation
	}
	// respond by RstStreamFrame with error code of STOPPING
	return s.sendFrame(NewRstStreamFrame(f.StreamID.GetValue(), qtype.Stopping, 0))
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

	LargestOffset qtype.QuicInt
}

func newRecvStream(streamID *qtype.StreamID, sess *Session) *RecvStream {
	sid := streamID.GetValue()
	h := &utils.Heap{}
	heap.Init(h)
	return &RecvStream{
		BaseStream: &BaseStream{
			ID:    *streamID,
			State: qtype.StreamRecv,
			sess:  sess,
			// TODO: need to check default MAX_DATA
			flowcontroller: &StreamFlowController{
				IsStreamZero: sid == 0,
				connFC:       sess.flowContoller,
				baseFlowController: baseFlowController{
					MaxDataLimit: 1024, // TODO: set appropriately
				},
			},
		},
		LargestOffset: qtype.QuicInt{0, 0, 1},
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
	if f.FinalOffset.Less(&s.LargestOffset) ||
		s.State == qtype.StreamSizeKnown && !f.FinalOffset.Equal(&s.LargestOffset) {
		return qtype.FinalOffsetError
	}

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
	err := s.flowcontroller.ReceivableByOffset(f.Offset.GetValue(), f.Finish)
	if err != nil {
		return err
	}

	if s.State == qtype.StreamSizeKnown {
		if s.LargestOffset.Less(f.Offset) {
			return qtype.FinalOffsetError
		}
	}

	if f.Finish {
		s.State = qtype.StreamSizeKnown
	}
	if s.LargestOffset.Less(f.Offset) {
		s.LargestOffset = *f.Offset
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
	sid := streamID.GetValue()
	return &SendRecvStream{
		BaseStream: &BaseStream{
			ID:    *streamID,
			State: qtype.StreamIdle,
			sess:  sess,
			// TODO: need to check default MAX_DATA
			flowcontroller: &StreamFlowController{
				IsStreamZero: sid == 0,
				connFC:       sess.flowContoller,
				baseFlowController: baseFlowController{
					MaxDataLimit: 1024, // TODO: set appropriately
				},
			},
		},
	}
}

func (s *SendRecvStream) handleRstStreamFrame(f *RstStreamFrame) error {
	s.State = qtype.StreamClosed
	return nil
}
