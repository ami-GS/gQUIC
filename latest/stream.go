package quiclatest

import (
	"container/heap"

	"github.com/ami-GS/gQUIC/latest/qtype"
	"github.com/ami-GS/gQUIC/latest/utils"
)

type Stream interface {
	GetState() qtype.StreamState
	GetID() qtype.StreamID
	Close()
	IsTerminated() bool
	QueueFrame(f StreamLevelFrame) error
	UpdateConnectionByteSent()
	UpdateConnectionByteReceived()
	UpdateStreamOffsetSent(offset uint64)
	UpdateStreamOffsetReceived(offset uint64)
	handleMaxStreamDataFrame(f *MaxStreamDataFrame) error
	handleStopSendingFrame(f *StopSendingFrame) error
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

func (s BaseStream) String() string {
	return fmt.Sprintf("%s, State:%s\n%s", s.ID, s.State, s.flowcontroller)
}

// blockedStreamFrames is just a ring buffer
type blockedStreamFrames struct {
	frames []*StreamFrame
	head   int
	tail   int
	size   int
}

func (bf *blockedStreamFrames) Empty() bool {
	return bf.head == bf.tail
}
func (bf *blockedStreamFrames) Full() bool {
	return bf.head == (bf.tail+1)%len(bf.frames)
}

func (bf *blockedStreamFrames) Enqueue(f *StreamFrame) {
	if bf.Full() {
		// TODO: error
	}
	bf.frames[bf.tail] = f
	bf.tail = (bf.tail + 1) % len(bf.frames)
	bf.size++
}

func (bf *blockedStreamFrames) Dequeue() *StreamFrame {
	if bf.Empty() {
		return nil
	}

	f := bf.frames[bf.head]
	bf.head = (bf.head + 1) % len(bf.frames)
	bf.size--
	return f
}
func (bf *blockedStreamFrames) Size() int {
	return bf.size
}

type SendStream struct {
	*BaseStream
	// application data can be buffered at "Ready" state
	SendBuffer            []byte
	blockedFramesOnStream blockedStreamFrames
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
		blockedFramesOnStream: blockedStreamFrames{
			frames: make([]*StreamFrame, 20),
		},
		// TODO : need to be able to set initial windowsize
		//FlowControllBlocked: false,
	}
}

func (s *SendStream) Close() {
	// implicitely close
	s.State = qtype.StreamDataRecvd
}

func (s SendStream) IsTerminated() bool {
	return s.State == qtype.StreamDataRecvd || s.State == qtype.StreamResetRecvd
}

// QueueFrame is used for validate the frame can be sent, and then queue the frame
func (s *SendStream) QueueFrame(f StreamLevelFrame) (err error) {
	if s.IsTerminated() {
		// MUST NOT send any frame in the states above
		return nil
	}

	switch frame := f.(type) {
	case *StreamFrame:
		if s.State == qtype.StreamResetSent {
			// MUST NOT send Stream frame in the states above
			return nil
		}
		dataOffset := frame.Offset.GetValue()
		switch s.flowcontroller.SendableByOffset(dataOffset, frame.Finish) {
		case Sendable:
			err = s.sendStreamFrame(frame)
		case StreamBlocked:
			s.blockedFramesOnStream.Enqueue(frame)
			err = s.QueueFrame(NewStreamBlockedFrame(s.GetID().GetValue(), dataOffset))
			return nil
		case ConnectionBlocked:
			s.sess.blockedFramesOnConnection.Enqueue(frame)
			err = s.sess.QueueFrame(NewBlockedFrame(dataOffset))
			return nil
		case BothBlocked:
			s.sess.blockedFramesOnConnection.Enqueue(frame) // avoid duplicate
			err = s.QueueFrame(NewStreamBlockedFrame(s.GetID().GetValue(), dataOffset))
			err = s.sess.QueueFrame(NewBlockedFrame(dataOffset))
			return nil
		}
	case *StreamBlockedFrame:
		if s.State == qtype.StreamResetSent {
			// MUST NOT send StreamBlocked frame in the states above
			return nil
		}
		err = s.sendStreamBlockedFrame(frame)
	case *RstStreamFrame:
		err = s.sendRstStreamFrame(frame)
	default:
		// TODO: error
		return nil
	}

	//qtype.MTUIPv4*0.8 is about 1000
	if f.(Frame).GetWireSize() >= 1000 {
		s.sess.sendFrameHPChan <- f.(Frame)
	} else {
		s.sess.sendFrameChan <- f.(Frame)
	}
	return err
}

func (s *SendStream) resendBlockedFrames() error {
	// TODO: be careful for multithread
	size := s.blockedFramesOnStream.Size()
	for i := 0; i < size; i++ {
		f := s.blockedFramesOnStream.Dequeue()
		err := s.QueueFrame(f)
		if err != nil {
			return err
		}
	}
	// send quickly
	s.sess.AssembleFrameChan <- struct{}{}
	return nil
}

func (s *SendStream) sendStreamFrame(f *StreamFrame) error {
	if s.State == qtype.StreamReady {
		s.State = qtype.StreamSend
	} else if s.State == qtype.StreamSend && f.Finish {
		s.State = qtype.StreamDataSent
	}
	s.UpdateStreamOffsetSent(f.Offset.GetValue())
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
	var err error
	if s.flowcontroller.MaxDataLimit < f.Data.GetValue() {
		s.flowcontroller.MaxDataLimit = f.Data.GetValue()

		// this doesn't send anything for the first MAX_STREAM_DATA frame for first setting
		err = s.resendBlockedFrames()
	}
	return err
}

// SendStream handle StopSending for receiving abondon request
func (s *SendStream) handleStopSendingFrame(f *StopSendingFrame) error {
	if s.State == qtype.StreamReady {
		return qtype.ProtocolViolation
	}
	// respond by RstStreamFrame with error code of STOPPING
	return s.QueueFrame(NewRstStreamFrame(f.StreamID.GetValue(), qtype.Stopping, 0))
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

	ReceiveAllDetector uint64
	LargestOffset      qtype.QuicInt
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

func (s *RecvStream) Close() {
	// implicitely close
	s.State = qtype.StreamDataRead
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
		copy(out[item.Offset-uint64(len(item.Data)):], item.Data)
	}

	s.State = qtype.StreamDataRead
	return out, false
}

// QueueFrame is used for validate the frame can be sent, and then queue the frame
func (s *RecvStream) QueueFrame(f StreamLevelFrame) (err error) {
	if s.IsTerminated() {
		// MUST NOT send any frame in the states above
		return nil
	}

	switch frame := f.(type) {
	case *MaxStreamDataFrame:
		err = s.sendMaxStreamDataFrame(frame)
	case *StopSendingFrame:
		err = s.sendStopSendingFrame(frame)
	default:
		// TODO: error
		return nil
	}

	s.sess.sendFrameChan <- f.(Frame)
	return err
}

func (s *RecvStream) sendMaxStreamDataFrame(f *MaxStreamDataFrame) error {
	//The receiver only sends MAX_STREAM_DATA in the "Recv" state
	if s.State != qtype.StreamRecv {
		return nil
	}
	if s.flowcontroller.MaxDataLimit < f.Data.GetValue() {
		s.flowcontroller.MaxDataLimit = f.Data.GetValue()
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

	offsetValue := f.Offset.GetValue()
	err := s.flowcontroller.ReceivableByOffset(offsetValue, f.Finish)
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
		s.DataSize = offsetValue
	}
	if s.LargestOffset.Less(f.Offset) {
		s.LargestOffset = *f.Offset
	}

	// TODO: copy workaround of data corrupting issue
	data := make([]byte, len(f.Data))
	copy(data, f.Data)
	heap.Push(s.ReorderBuffer, &utils.Item{offsetValue, data})

	s.ReceiveAllDetector = s.ReceiveAllDetector ^ offsetValue ^ (offsetValue - f.Length.GetValue())
	if s.State == qtype.StreamSizeKnown && s.ReceiveAllDetector != 0 && s.ReceiveAllDetector == s.DataSize {
		s.State = qtype.StreamDataRecvd
		// bellow is ugly
		s.sess.streamManager.finishedStreams.Enqueue(s)
	}

	s.UpdateStreamOffsetReceived(f.Offset.GetValue())
	return nil
}

func (s *RecvStream) handleStreamBlockedFrame(f *StreamBlockedFrame) error {
	if s.State == qtype.StreamDataRecvd {
		// ignore after receiving all data
		return nil
	}
	return s.QueueFrame(NewMaxStreamDataFrame(f.GetStreamID().GetValue(), f.Offset.GetValue()))
}

type SendRecvStream struct {
	*BaseStream
	*SendStream
	*RecvStream
}

func newSendRecvStream(streamID *qtype.StreamID, sess *Session) *SendRecvStream {
	return &SendRecvStream{
		BaseStream: &BaseStream{
			ID:    *streamID,
			State: qtype.StreamIdle,
			sess:  sess,
			// flow controll should be done in each send and recv stream bellows?
			flowcontroller: nil,
		},
		SendStream: newSendStream(streamID, sess),
		RecvStream: newRecvStream(streamID, sess),
	}
}

func (s *SendRecvStream) handleRstStreamFrame(f *RstStreamFrame) error {
	err := s.RecvStream.handleRstStreamFrame(f)
	if err != nil {
		return err
	}
	if s.RecvStream.State == qtype.StreamResetRecvd {
		if s.SendStream.State == qtype.StreamReady || s.SendStream.State == qtype.StreamSend || s.SendStream.State == qtype.StreamDataSent {
			s.State = qtype.StreamHalfClosed
		} else {
			s.State = qtype.StreamClosed
		}
	} else {
		// would be impossible to reach here
	}
	return nil
}
func (s *SendRecvStream) handleMaxStreamDataFrame(f *MaxStreamDataFrame) error {
	return s.SendStream.handleMaxStreamDataFrame(f)
}
func (s *SendRecvStream) handleStopSendingFrame(f *StopSendingFrame) error {
	return s.SendStream.handleStopSendingFrame(f)
}
func (s *SendRecvStream) handleStreamBlockedFrame(f *StreamBlockedFrame) error {
	return s.RecvStream.handleStreamBlockedFrame(f)
}
func (s *SendRecvStream) handleStreamFrame(f *StreamFrame) error {
	err := s.RecvStream.handleStreamFrame(f)
	if err != nil {
		return err
	}

	if s.RecvStream.State == qtype.StreamSizeKnown {
		if s.SendStream.State == qtype.StreamReady || s.SendStream.State == qtype.StreamSend || s.SendStream.State == qtype.StreamDataSent {
			s.State = qtype.StreamOpen
		} else if s.SendStream.State == qtype.StreamDataRecvd || s.SendStream.State == qtype.StreamResetSent || s.SendStream.State == qtype.StreamResetRecvd {
			s.State = qtype.StreamHalfClosed
		}
	} else if s.RecvStream.State == qtype.StreamDataRecvd {
		if s.SendStream.State == qtype.StreamDataRecvd || s.SendStream.State == qtype.StreamResetSent || s.SendStream.State == qtype.StreamResetRecvd {
			s.State = qtype.StreamClosed
		} else if s.SendStream.State == qtype.StreamReady || s.SendStream.State == qtype.StreamSend || s.SendStream.State == qtype.StreamDataSent {
			s.State = qtype.StreamHalfClosed
		}
	}
	return nil
}

func (s *SendRecvStream) Close() {
	// implicitely close
	s.SendStream.Close()
	s.RecvStream.Close()
	s.State = qtype.StreamClosed
}

func (s *SendRecvStream) IsTerminated() bool {
	// TODO: currently s.State doesn't care after sending frame
	return s.State == qtype.StreamClosed
}

func (s *SendRecvStream) QueueFrame(f StreamLevelFrame) error {
	var err error
	switch f.(type) {
	case *StreamFrame, *StreamBlockedFrame, *RstStreamFrame:
		err = s.SendStream.QueueFrame(f)
	case *MaxStreamIDFrame, *StopSendingFrame:
		err = s.RecvStream.QueueFrame(f)
	}
	// TODO: change s.State
	return err
}
