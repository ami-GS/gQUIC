package quiclatest

import (
	"encoding/binary"
	"fmt"

	"github.com/ami-GS/gQUIC/latest/qtype"
)

type Frame interface {
	GetWire() []byte
	genWire() ([]byte, error)
	String() string
	GetType() FrameType
	GetWireSize() int
}

type StreamLevelFrame interface {
	GetStreamID() qtype.StreamID
}

type BaseStreamLevelFrame struct {
	StreamID qtype.StreamID
}

func (s *BaseStreamLevelFrame) String() string {
	return fmt.Sprintf("%s", s.StreamID)
}

func (s *BaseStreamLevelFrame) GetStreamID() qtype.StreamID {
	return s.StreamID
}

type FrameParser func(data []byte) (Frame, int, error)

var FrameParserMap = map[FrameType]FrameParser{
	PaddingFrameType:          ParsePaddingFrame,
	RstStreamFrameType:        ParseRstStreamFrame,
	ConnectionCloseFrameType:  ParseConnectionCloseFrame,
	ApplicationCloseFrameType: ParseApplicationCloseFrame,
	MaxDataFrameType:          ParseMaxDataFrame,
	MaxStreamDataFrameType:    ParseMaxStreamDataFrame,
	MaxStreamIDFrameType:      ParseMaxStreamIDFrame,
	PingFrameType:             ParsePingFrame,
	BlockedFrameType:          ParseBlockedFrame,
	StreamBlockedFrameType:    ParseStreamBlockedFrame,
	StreamIDBlockedFrameType:  ParseStreamIDBlockedFrame,
	NewConnectionIDFrameType:  ParseNewConnectionIDFrame,
	StopSendingFrameType:      ParseStopSendingFrame,
	AckFrameType:              ParseAckFrame,
	PathChallengeFrameType:    ParsePathChallengeFrame,
	PathResponseFrameType:     ParsePathResponseFrame,

	// type should be (type & StreamFrameTypeCommon)
	StreamFrameType: ParseStreamFrame,
}

type FrameType uint8

const (
	PaddingFrameType FrameType = iota
	RstStreamFrameType
	ConnectionCloseFrameType
	ApplicationCloseFrameType
	MaxDataFrameType
	MaxStreamDataFrameType
	MaxStreamIDFrameType
	PingFrameType
	BlockedFrameType
	StreamBlockedFrameType
	StreamIDBlockedFrameType
	NewConnectionIDFrameType
	StopSendingFrameType
	AckFrameType
	PathChallengeFrameType
	PathResponseFrameType
	StreamFrameType       // 0x10-0x17
	StreamFrameTypeCommon = 0x10
)

func (frameType FrameType) String() string {
	names := []string{
		"PADDING",
		"RST_STREAM",
		"CONNECTION_CLOSE",
		"APPLICATION_CLOSE",
		"MAX_DATA",
		"MAX_STREAM_DATA",
		"MAX_STREAM_ID",
		"PING",
		"BLOCKED",
		"STREAM_BLOCKED",
		"STREAM_ID_BLOCKED",
		"NEW_CONNECTION_ID",
		"STOP_SENDING",
		"ACK",
		"PATH_CHALLENGE",
		"PATH_RESPONSE",
		"STREAM",
	}
	if 0x10 <= frameType && frameType <= 0x17 {
		return "STREAM"
	} else if frameType > 0x17 {
		return "NO_SUCH_TYPE"
	}
	return names[int(frameType)]
}

type BaseFrame struct {
	Type FrameType
	wire []byte
}

func NewBaseFrame(frameType FrameType) *BaseFrame {
	return &BaseFrame{
		Type: frameType,
	}
}

func (f *BaseFrame) GetType() FrameType {
	return f.Type
}

func (f *BaseFrame) GetWire() []byte {
	return f.wire
}

func (f *BaseFrame) GetWireSize() int {
	return len(f.wire)
}

func (f *BaseFrame) String() string {
	return f.Type.String()
}

func ParseFrame(data []byte) (f Frame, idx int, err error) {
	if data[0] > 0x17 {
		// TODO: error needed, but not decided
		return nil, 0, qtype.ProtocolViolation
	}
	if data[0]&StreamFrameTypeCommon == StreamFrameTypeCommon {
		return FrameParserMap[StreamFrameTypeCommon](data)
	}
	return FrameParserMap[FrameType(data[0])](data)
}

func ParseFrames(data []byte) (fs []Frame, idx int, err error) {
	// TODO: or call parallel?
	for idx < len(data) {
		// Ping as well?
		if FrameType(data[idx]) == PaddingFrameType {
			// skip when padding frame to reduce cost
			// is return better?
			idx++
			continue
		}

		f, oneLen, err := ParseFrame(data[idx:])
		if err != nil {
			return nil, idx + oneLen, err
		}

		fs = append(fs, f)
		idx += oneLen
	}
	return fs, idx, nil
}

func GetFrameWires(frames []Frame) (allWire []byte, err error) {
	for _, frame := range frames {
		wire := frame.GetWire()
		// TODO: looks slow
		allWire = append(allWire, wire...)
	}
	return allWire, err
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Error Code (16)     |   Reason Phrase Length (i)  ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Reason Phrase (*)                    ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type ConnectionCloseFrame struct {
	*BaseFrame
	ErrorCode    qtype.TransportError
	ReasonLength qtype.QuicInt
	Reason       string
}

func NewConnectionCloseFrame(errorCode qtype.TransportError, reason string) *ConnectionCloseFrame {
	f := &ConnectionCloseFrame{
		BaseFrame:    NewBaseFrame(ConnectionCloseFrameType),
		ErrorCode:    errorCode,
		ReasonLength: qtype.QuicInt(uint64(len(reason))),
		Reason:       reason,
	}
	var err error
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseConnectionCloseFrame(data []byte) (Frame, int, error) {
	f := &ConnectionCloseFrame{
		BaseFrame: NewBaseFrame(ConnectionCloseFrameType),
	}
	idx := 1
	f.ErrorCode = qtype.TransportError(binary.BigEndian.Uint16(data[idx:]))
	// TODO: check whether the code exists
	idx += 2
	f.ReasonLength = qtype.DecodeQuicInt(data[idx:])
	idx += f.ReasonLength.GetByteLen()
	f.Reason = string(data[idx : idx+int(f.ReasonLength)])
	idx += int(f.ReasonLength)
	f.wire = data[:idx]

	return f, idx, nil
}

func (f ConnectionCloseFrame) String() string {
	return fmt.Sprintf("[%s]\n\tErrCode:%s\tReason:%s(%d)", f.BaseFrame, f.ErrorCode, f.Reason, f.ReasonLength)
}

func (f ConnectionCloseFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 3+f.ReasonLength.GetByteLen()+len(f.Reason))
	wire[0] = byte(ConnectionCloseFrameType)
	binary.BigEndian.PutUint16(wire[1:], uint16(f.ErrorCode))
	idx := f.ReasonLength.PutWire(wire[3:]) + 3
	copy(wire[idx:], []byte(f.Reason))
	return
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Error Code (16)     |   Reason Phrase Length (i)  ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Reason Phrase (*)                    ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type ApplicationCloseFrame struct {
	*BaseFrame
	ErrorCode    qtype.ApplicationError
	ReasonLength qtype.QuicInt
	Reason       string
}

func NewApplicationCloseFrame(errorCode qtype.ApplicationError, reason string) *ApplicationCloseFrame {
	f := &ApplicationCloseFrame{
		BaseFrame:    NewBaseFrame(ApplicationCloseFrameType),
		ErrorCode:    errorCode,
		ReasonLength: qtype.QuicInt(uint64(len(reason))),
		Reason:       reason,
	}
	var err error
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseApplicationCloseFrame(data []byte) (Frame, int, error) {
	f := &ApplicationCloseFrame{
		BaseFrame: NewBaseFrame(ApplicationCloseFrameType),
	}
	idx := 1
	f.ErrorCode = qtype.ApplicationError(binary.BigEndian.Uint16(data[idx:]))
	// TODO: check whether the code exists
	idx += 2
	f.ReasonLength = qtype.DecodeQuicInt(data[idx:])
	idx += f.ReasonLength.GetByteLen()
	f.Reason = string(data[idx : idx+int(f.ReasonLength)])
	idx += int(f.ReasonLength)
	f.wire = data[:idx]

	return f, idx, nil
}

func (f ApplicationCloseFrame) String() string {
	return fmt.Sprintf("[%s]\n\tErrCode:%s\tReason:%s(%d)", f.BaseFrame, f.ErrorCode, f.Reason, f.ReasonLength)
}

func (f ApplicationCloseFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 3+f.ReasonLength.GetByteLen()+len(f.Reason))
	wire[0] = byte(ApplicationCloseFrameType)
	binary.BigEndian.PutUint16(wire[1:], uint16(f.ErrorCode))
	idx := f.ReasonLength.PutWire(wire[3:]) + 3
	copy(wire[idx:], []byte(f.Reason))
	return
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Stream ID (i)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Application Error Code (16)  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Final Offset (i)                     ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type RstStreamFrame struct {
	*BaseFrame
	*BaseStreamLevelFrame
	ErrorCode   qtype.ApplicationError
	FinalOffset qtype.QuicInt
}

func NewRstStreamFrame(streamID qtype.StreamID, errorCode qtype.ApplicationError, offset qtype.QuicInt) *RstStreamFrame {
	f := &RstStreamFrame{
		BaseFrame:            NewBaseFrame(RstStreamFrameType),
		BaseStreamLevelFrame: &BaseStreamLevelFrame{streamID},
		ErrorCode:            errorCode,
		FinalOffset:          offset,
	}
	var err error
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseRstStreamFrame(data []byte) (Frame, int, error) {
	idx := 1
	frame := &RstStreamFrame{
		BaseFrame:            NewBaseFrame(RstStreamFrameType),
		BaseStreamLevelFrame: &BaseStreamLevelFrame{},
	}
	// TODO: bellow is not cool
	frame.StreamID = qtype.StreamID(qtype.DecodeQuicInt(data[idx:]))
	idx += qtype.QuicInt(frame.StreamID).GetByteLen()
	frame.ErrorCode = qtype.ApplicationError(binary.BigEndian.Uint16(data[idx:]))
	idx += 2
	frame.FinalOffset = qtype.DecodeQuicInt(data[idx:])
	idx += frame.FinalOffset.GetByteLen()
	frame.wire = data[:idx]

	return frame, idx, nil
}

func (f RstStreamFrame) String() string {
	return fmt.Sprintf("[%s] %s\n\tErrCode:%s\tFinalOffset:%d", f.BaseFrame, f.BaseStreamLevelFrame, f.ErrorCode, f.FinalOffset)
}

func (f RstStreamFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 1+qtype.QuicInt(f.StreamID).GetByteLen()+2+f.FinalOffset.GetByteLen())
	wire[0] = byte(RstStreamFrameType)
	idx := f.StreamID.PutWire(wire[1:]) + 1
	binary.BigEndian.PutUint16(wire[idx:], uint16(f.ErrorCode))
	idx += 2
	idx += f.FinalOffset.PutWire(wire[idx:])
	return wire, nil
}

type PaddingFrame struct {
	*BaseFrame
}

func NewPaddingFrame() *PaddingFrame {
	var err error
	f := &PaddingFrame{
		BaseFrame: NewBaseFrame(PaddingFrameType),
	}
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParsePaddingFrame(data []byte) (Frame, int, error) {
	frame := &PaddingFrame{
		BaseFrame: NewBaseFrame(PaddingFrameType),
	}
	frame.wire = data[:1]
	return frame, 1, nil
}

func (f PaddingFrame) String() string {
	return fmt.Sprintf("[%s]\n", f.BaseFrame)
}

func (f PaddingFrame) genWire() (wire []byte, err error) {
	return []byte{0x00}, nil
}

type PingFrame struct {
	*BaseFrame
}

func NewPingFrame() *PingFrame {
	f := &PingFrame{
		BaseFrame: NewBaseFrame(PingFrameType),
	}
	f.wire, _ = f.genWire()
	return f
}

func ParsePingFrame(data []byte) (Frame, int, error) {
	f := &PingFrame{
		BaseFrame: NewBaseFrame(PingFrameType),
	}
	f.wire = data[:1]
	return f, 1, nil // only header
}

func (f PingFrame) String() string {
	return fmt.Sprintf("[%s]", f.BaseFrame)
}

func (f PingFrame) genWire() (wire []byte, err error) {
	return []byte{0x07}, nil
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Maximum Data (i)                     ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type MaxDataFrame struct {
	*BaseFrame
	Data qtype.QuicInt
}

func NewMaxDataFrame(maxData qtype.QuicInt) *MaxDataFrame {
	f := &MaxDataFrame{
		BaseFrame: NewBaseFrame(MaxDataFrameType),
		Data:      maxData,
	}
	var err error
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseMaxDataFrame(data []byte) (Frame, int, error) {
	f := &MaxDataFrame{
		BaseFrame: NewBaseFrame(MaxDataFrameType),
	}
	f.Data = qtype.DecodeQuicInt(data[1:])
	f.wire = data[:1+f.Data.GetByteLen()]

	return f, 1 + f.Data.GetByteLen(), nil
}

func (f MaxDataFrame) String() string {
	return fmt.Sprintf("[%s]\n\tMax Data:%d", f.BaseFrame, f.Data)
}

func (f MaxDataFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 1+f.Data.GetByteLen())
	wire[0] = byte(MaxDataFrameType)
	f.Data.PutWire(wire[1:])
	return
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Stream ID (i)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Maximum Stream Data (i)                  ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type MaxStreamDataFrame struct {
	*BaseFrame
	*BaseStreamLevelFrame
	Data qtype.QuicInt
}

func NewMaxStreamDataFrame(streamID qtype.StreamID, maxData qtype.QuicInt) *MaxStreamDataFrame {
	f := &MaxStreamDataFrame{
		BaseFrame:            NewBaseFrame(MaxStreamDataFrameType),
		BaseStreamLevelFrame: &BaseStreamLevelFrame{streamID},
		Data:                 maxData,
	}
	var err error
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseMaxStreamDataFrame(data []byte) (Frame, int, error) {
	f := &MaxStreamDataFrame{
		BaseFrame:            NewBaseFrame(MaxStreamDataFrameType),
		BaseStreamLevelFrame: &BaseStreamLevelFrame{},
	}
	f.StreamID = qtype.StreamID(qtype.DecodeQuicInt(data[1:]))
	f.Data = qtype.DecodeQuicInt(data[1+qtype.QuicInt(f.StreamID).GetByteLen():])
	idx := 1 + qtype.QuicInt(f.StreamID).GetByteLen() + f.Data.GetByteLen()
	f.wire = data[:idx]
	return f, idx, nil
}

func (f MaxStreamDataFrame) String() string {
	return fmt.Sprintf("[%s] %s\n\tMax Stream Data:%d", f.BaseFrame, f.BaseStreamLevelFrame, f.Data)
}

func (f MaxStreamDataFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 1+qtype.QuicInt(f.StreamID).GetByteLen()+f.Data.GetByteLen())
	wire[0] = byte(MaxStreamDataFrameType)
	idx := f.StreamID.PutWire(wire[1:]) + 1
	f.Data.PutWire(wire[idx:])
	return
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Maximum Stream ID (i)                    ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type MaxStreamIDFrame struct {
	*BaseFrame
	*BaseStreamLevelFrame
}

func NewMaxStreamIDFrame(streamID qtype.StreamID) *MaxStreamIDFrame {
	f := &MaxStreamIDFrame{
		BaseFrame:            NewBaseFrame(MaxStreamIDFrameType),
		BaseStreamLevelFrame: &BaseStreamLevelFrame{streamID},
	}
	var err error
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseMaxStreamIDFrame(data []byte) (Frame, int, error) {
	f := &MaxStreamIDFrame{
		BaseFrame:            NewBaseFrame(MaxStreamIDFrameType),
		BaseStreamLevelFrame: &BaseStreamLevelFrame{},
	}
	f.StreamID = qtype.StreamID(qtype.DecodeQuicInt(data[1:]))
	idx := 1 + qtype.QuicInt(f.StreamID).GetByteLen()
	f.wire = data[:idx]
	return f, idx, nil
}

func (f MaxStreamIDFrame) String() string {
	return fmt.Sprintf("[%s]\n\t Max Stream ID:%d", f.BaseFrame, f.BaseStreamLevelFrame.StreamID)
}

func (f MaxStreamIDFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 1+qtype.QuicInt(f.StreamID).GetByteLen())
	wire[0] = byte(MaxStreamIDFrameType)
	f.StreamID.PutWire(wire[1:])
	return
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Offset (i)                         ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type BlockedFrame struct {
	*BaseFrame
	Offset qtype.QuicInt
}

func NewBlockedFrame(offset qtype.QuicInt) *BlockedFrame {
	f := &BlockedFrame{
		BaseFrame: NewBaseFrame(BlockedFrameType),
		Offset:    offset,
	}
	var err error
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseBlockedFrame(data []byte) (Frame, int, error) {
	f := &BlockedFrame{
		BaseFrame: NewBaseFrame(BlockedFrameType),
	}
	f.Offset = qtype.DecodeQuicInt(data[1:])
	idx := 1 + f.Offset.GetByteLen()
	f.wire = data[:idx]
	return f, idx, nil
}

func (f BlockedFrame) String() string {
	return fmt.Sprintf("[%s]\n\tOffset:%d", f.BaseFrame, f.Offset)
}

func (f BlockedFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 1+f.Offset.GetByteLen())
	wire[0] = byte(BlockedFrameType)
	f.Offset.PutWire(wire[1:])
	return
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Stream ID (i)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Offset (i)                          ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type StreamBlockedFrame struct {
	*BaseFrame
	*BaseStreamLevelFrame
	Offset qtype.QuicInt
}

func NewStreamBlockedFrame(streamID qtype.StreamID, offset qtype.QuicInt) *StreamBlockedFrame {
	f := &StreamBlockedFrame{
		BaseFrame:            NewBaseFrame(StreamBlockedFrameType),
		BaseStreamLevelFrame: &BaseStreamLevelFrame{streamID},
		Offset:               offset,
	}
	var err error
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseStreamBlockedFrame(data []byte) (Frame, int, error) {
	f := &StreamBlockedFrame{
		BaseFrame:            NewBaseFrame(StreamBlockedFrameType),
		BaseStreamLevelFrame: &BaseStreamLevelFrame{},
	}
	f.StreamID = qtype.StreamID(qtype.DecodeQuicInt(data[1:]))
	idx := 1 + qtype.QuicInt(f.StreamID).GetByteLen()
	f.Offset = qtype.DecodeQuicInt(data[idx:])
	idx += f.Offset.GetByteLen()
	f.wire = data[:idx]
	return f, idx, nil
}

func (f StreamBlockedFrame) String() string {
	return fmt.Sprintf("[%s] %s\n\tOffset:%d", f.BaseFrame, f.BaseStreamLevelFrame, f.Offset)
}

func (f StreamBlockedFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 1+qtype.QuicInt(f.StreamID).GetByteLen()+f.Offset.GetByteLen())
	wire[0] = byte(StreamBlockedFrameType)
	f.StreamID.PutWire(wire[1:])
	f.Offset.PutWire(wire[1+qtype.QuicInt(f.StreamID).GetByteLen():])
	return
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Stream ID (i)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type StreamIDBlockedFrame struct {
	*BaseFrame
	*BaseStreamLevelFrame
}

func NewStreamIDBlockedFrame(streamID qtype.StreamID) *StreamIDBlockedFrame {
	f := &StreamIDBlockedFrame{
		BaseFrame:            NewBaseFrame(StreamIDBlockedFrameType),
		BaseStreamLevelFrame: &BaseStreamLevelFrame{streamID},
	}
	var err error
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseStreamIDBlockedFrame(data []byte) (Frame, int, error) {
	f := &StreamIDBlockedFrame{
		BaseFrame:            NewBaseFrame(StreamIDBlockedFrameType),
		BaseStreamLevelFrame: &BaseStreamLevelFrame{},
	}
	f.StreamID = qtype.StreamID(qtype.DecodeQuicInt(data[1:]))
	idx := 1 + qtype.QuicInt(f.StreamID).GetByteLen()
	f.wire = data[:1+qtype.QuicInt(f.StreamID).GetByteLen()]
	return f, idx, nil
}

func (f StreamIDBlockedFrame) String() string {
	return fmt.Sprintf("[%s]\n\tStreamID:%d", f.BaseFrame, f.StreamID)
}

func (f StreamIDBlockedFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 1+qtype.QuicInt(f.StreamID).GetByteLen())
	wire[0] = byte(StreamIDBlockedFrameType)
	f.StreamID.PutWire(wire[1:])
	return
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Sequence (i)                       ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Length (8)  |          Connection ID (32..144)            ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                   Stateless Reset Token (128)                 +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type NewConnectionIDFrame struct {
	*BaseFrame
	Sequence        qtype.QuicInt
	Length          byte
	ConnID          qtype.ConnectionID
	StatelessRstTkn [16]byte
}

func NewNewConnectionIDFrame(sequence qtype.QuicInt, length byte, connID qtype.ConnectionID, stateLessRstTkn [16]byte) *NewConnectionIDFrame {
	f := &NewConnectionIDFrame{
		BaseFrame:       NewBaseFrame(NewConnectionIDFrameType),
		Sequence:        sequence,
		Length:          length,
		ConnID:          connID,
		StatelessRstTkn: stateLessRstTkn,
	}
	var err error
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseNewConnectionIDFrame(data []byte) (Frame, int, error) {
	var err error
	idx := 1
	f := &NewConnectionIDFrame{
		BaseFrame: NewBaseFrame(NewConnectionIDFrameType),
	}
	f.Sequence = qtype.DecodeQuicInt(data[idx:])
	f.Length = data[idx+f.Sequence.GetByteLen()]
	if f.Length < 4 || 18 < f.Length {
		return nil, 0, qtype.ProtocolViolation
	}
	idx += f.Sequence.GetByteLen() + 1
	f.ConnID, err = qtype.ReadConnectionID(data[idx:], int(f.Length))
	if err != nil {
		return nil, 0, err
	}
	idx += int(f.Length)
	copy(f.StatelessRstTkn[:], data[idx:idx+16])
	idx += 16
	f.wire = data[:idx]
	return f, idx, nil
}

func (f NewConnectionIDFrame) String() string {
	return fmt.Sprintf("[%s]\n\tSeq:%d\tLen:%d\tConnID:%s\n\tStateless Reset Token:%s", f.BaseFrame, f.Sequence, f.Length, f.ConnID, string(f.StatelessRstTkn[:]))
}

func (f NewConnectionIDFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 18+len(f.ConnID)+f.Sequence.GetByteLen())
	wire[0] = byte(NewConnectionIDFrameType)
	idx := f.Sequence.PutWire(wire) + 1
	wire[idx] += f.Length
	copy(wire[idx+1:], f.ConnID.Bytes())
	idx += len(f.ConnID) + 1
	copy(wire[idx:], f.StatelessRstTkn[:])
	return
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Stream ID (i)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Application Error Code (16)  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type StopSendingFrame struct {
	*BaseFrame
	*BaseStreamLevelFrame
	ErrorCode qtype.ApplicationError
}

func NewStopSendingFrame(streamID qtype.StreamID, errCode qtype.ApplicationError) *StopSendingFrame {
	f := &StopSendingFrame{
		BaseFrame:            NewBaseFrame(StopSendingFrameType),
		BaseStreamLevelFrame: &BaseStreamLevelFrame{streamID},
		ErrorCode:            errCode,
	}
	var err error
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseStopSendingFrame(data []byte) (Frame, int, error) {
	f := &StopSendingFrame{
		BaseFrame:            NewBaseFrame(StopSendingFrameType),
		BaseStreamLevelFrame: &BaseStreamLevelFrame{},
	}
	f.StreamID = qtype.StreamID(qtype.DecodeQuicInt(data[1:]))
	f.ErrorCode = qtype.ApplicationError(binary.BigEndian.Uint16(data[1+qtype.QuicInt(f.StreamID).GetByteLen():]))
	f.wire = data[:qtype.QuicInt(f.StreamID).GetByteLen()+3]
	return f, qtype.QuicInt(f.StreamID).GetByteLen() + 3, nil
}

func (f StopSendingFrame) String() string {
	return fmt.Sprintf("[%s] %s\n\tErr:%s", f.BaseFrame, f.BaseStreamLevelFrame, f.ErrorCode)
}

func (f StopSendingFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, qtype.QuicInt(f.StreamID).GetByteLen()+3)
	wire[0] = byte(StopSendingFrameType)
	f.StreamID.PutWire(wire[1:])
	binary.BigEndian.PutUint16(wire[1+qtype.QuicInt(f.StreamID).GetByteLen():], uint16(f.ErrorCode))
	return
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Largest Acknowledged (i)                ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          ACK Delay (i)                      ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       ACK Block Count (i)                   ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          ACK Blocks (*)                     ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type AckBlock struct {
	Block qtype.QuicInt
	Gap   qtype.QuicInt
}

type AckFrame struct {
	*BaseFrame
	LargestAcked  qtype.QuicInt
	AckDelay      qtype.QuicInt
	AckBlockCount qtype.QuicInt
	AckBlocks     []AckBlock
}

func NewAckFrame(lAcked, ackDelay qtype.QuicInt, ackBlocks []AckBlock) *AckFrame {
	if ackBlocks == nil {
		return nil
	}
	f := &AckFrame{
		BaseFrame:     NewBaseFrame(AckFrameType),
		LargestAcked:  lAcked,
		AckDelay:      ackDelay,
		AckBlockCount: qtype.QuicInt(uint64(len(ackBlocks) - 1)),
		AckBlocks:     ackBlocks,
	}
	var err error
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseAckFrame(data []byte) (Frame, int, error) {
	f := &AckFrame{
		BaseFrame: NewBaseFrame(AckFrameType),
	}
	idx := 1
	f.LargestAcked = qtype.DecodeQuicInt(data[idx:])
	idx += f.LargestAcked.GetByteLen()
	f.AckDelay = qtype.DecodeQuicInt(data[idx:])
	idx += f.AckDelay.GetByteLen()
	f.AckBlockCount = qtype.DecodeQuicInt(data[idx:])
	idx += f.AckBlockCount.GetByteLen()
	f.AckBlocks = make([]AckBlock, 1+f.AckBlockCount)

	f.AckBlocks[0].Block = qtype.DecodeQuicInt(data[idx:])
	idx += f.AckBlocks[0].Block.GetByteLen()
	for i := uint64(1); i < uint64(f.AckBlockCount); i++ {
		f.AckBlocks[i].Gap = qtype.DecodeQuicInt(data[idx:])
		idx += f.AckBlocks[i].Gap.GetByteLen()
		f.AckBlocks[i].Block = qtype.DecodeQuicInt(data[idx:])
		idx += f.AckBlocks[i].Block.GetByteLen()
	}
	f.wire = data[:idx]
	return f, idx, nil
}

func (f AckFrame) String() string {
	out := fmt.Sprintf("[%s]\n\tLargest:%d\tDelay:%d\tBlkCount:%d\n\tFirstAck:%d", f.BaseFrame, f.LargestAcked, f.AckDelay, f.AckBlockCount, f.AckBlocks[0].Block)
	for i := 1; i < int(f.AckBlockCount); i++ {
		out += fmt.Sprintf("\n\tAck:%d\tGap:%d", f.AckBlocks[i].Block, f.AckBlocks[i].Gap)
	}
	return out
}

func (f AckFrame) genWire() (wire []byte, err error) {
	blockByteLen := 0
	for _, v := range f.AckBlocks {
		blockByteLen += v.Block.GetByteLen() + v.Gap.GetByteLen()
	}
	wire = make([]byte, 1+f.LargestAcked.GetByteLen()+f.AckDelay.GetByteLen()+f.AckBlockCount.GetByteLen()+blockByteLen)
	wire[0] = byte(AckFrameType)
	idx := f.LargestAcked.PutWire(wire[1:]) + 1
	idx += f.AckDelay.PutWire(wire[idx:])
	idx += f.AckBlockCount.PutWire(wire[idx:])

	idx += f.AckBlocks[0].Block.PutWire(wire[idx:])
	for i := uint64(1); i < uint64(f.AckBlockCount); i++ {
		v := f.AckBlocks[i]
		idx += v.Gap.PutWire(wire[idx:])
		idx += v.Block.PutWire(wire[idx:])
	}

	return
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                            Data (8)                           +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type PathChallengeFrame struct {
	*BaseFrame
	Data [8]byte
}

func NewPathChallengeFrame(data [8]byte) *PathChallengeFrame {
	var err error
	f := &PathChallengeFrame{
		BaseFrame: NewBaseFrame(PathChallengeFrameType),
		Data:      data,
	}
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParsePathChallengeFrame(data []byte) (Frame, int, error) {
	f := &PathChallengeFrame{
		BaseFrame: NewBaseFrame(PathChallengeFrameType),
	}
	copy(f.Data[:], data[1:9])
	f.wire = data[:9]
	return f, 9, nil
}

func (f PathChallengeFrame) String() string {
	return fmt.Sprintf("[%s]\n\tData:%v", f.BaseFrame, f.Data)
}

func (f PathChallengeFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 9)
	wire[0] = byte(PathChallengeFrameType)
	copy(wire[1:], f.Data[:])
	return wire, nil
}

type PathResponseFrame struct {
	*BaseFrame
	Data [8]byte
}

func NewPathResponseFrame(data [8]byte) *PathResponseFrame {
	var err error
	f := &PathResponseFrame{
		BaseFrame: NewBaseFrame(PathResponseFrameType),
		Data:      data,
	}
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParsePathResponseFrame(data []byte) (Frame, int, error) {
	f := &PathResponseFrame{
		BaseFrame: NewBaseFrame(PathResponseFrameType),
	}
	copy(f.Data[:], data[1:9])
	f.wire = data[:9]
	return f, 9, nil
}

func (f PathResponseFrame) String() string {
	return fmt.Sprintf("[%s]\n\tData:%v", f.BaseFrame, f.Data)
}

func (f PathResponseFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 9)
	wire[0] = byte(PathResponseFrameType)
	copy(wire[1:], f.Data[:])
	return wire, nil
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Stream ID (i)                       ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         [Offset (i)]                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         [Length (i)]                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Stream Data (*)                      ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type StreamFrame struct {
	*BaseFrame
	*BaseStreamLevelFrame
	Offset qtype.QuicInt
	Length qtype.QuicInt
	Finish bool
	Data   []byte
}

func NewStreamFrame(streamID qtype.StreamID, offset qtype.QuicInt, offF, lenF, fin bool, data []byte) *StreamFrame {
	typeFlag := StreamFrameType
	if offF {
		typeFlag |= 0x04
	}
	length := qtype.QuicInt(0)
	if lenF {
		typeFlag |= 0x02
		if data != nil {
			length = qtype.QuicInt(uint64(len(data)))
		}
	}
	if fin {
		typeFlag |= 0x01
	}

	f := &StreamFrame{
		BaseFrame:            NewBaseFrame(typeFlag),
		BaseStreamLevelFrame: &BaseStreamLevelFrame{streamID},
		Offset:               offset,
		Length:               length,
		Finish:               fin,
		Data:                 data,
	}
	var err error
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseStreamFrame(data []byte) (Frame, int, error) {
	// TODO: Error, empty data is allowed only when FIN == 1 or offset == 0
	idx := 1
	flag := data[0] & 0x07
	f := &StreamFrame{
		BaseFrame:            NewBaseFrame(StreamFrameType | FrameType(flag)),
		BaseStreamLevelFrame: &BaseStreamLevelFrame{},
	}

	f.StreamID = qtype.StreamID(qtype.DecodeQuicInt(data[idx:]))

	idx += qtype.QuicInt(f.StreamID).GetByteLen()
	// OFF bit
	if flag&0x04 == 0x04 {
		f.Type |= 0x04
		f.Offset = qtype.DecodeQuicInt(data[idx:])
		idx += f.Offset.GetByteLen()
	}

	// LEN bit
	if flag&0x02 == 0x02 {
		f.Type |= 0x02
		f.Length = qtype.DecodeQuicInt(data[idx:])
		idx += f.Length.GetByteLen()
		f.Data = data[idx : uint64(idx)+uint64(f.Length)]
		idx += int(f.Length)
	} else {
		if len(data)-idx == 0 {
			f.Data = nil
		} else {
			f.Data = data[idx:]
			idx += len(data) - idx
		}
	}

	// FIN bit
	if flag&0x01 == 0x01 {
		f.Type |= 0x01
		f.Finish = true
	}
	f.wire = data[:idx]
	return f, idx, nil
}

func (f StreamFrame) String() string {
	offset := "absent"
	if f.Type&0x04 == 0x04 {
		offset = fmt.Sprintf("%d", f.Offset)
	}
	length := "absent"
	if f.Type&0x02 == 0x02 {
		length = fmt.Sprintf("%d", f.Length)
	}

	return fmt.Sprintf("[%s] %s\n\tOffset:%s\tLength:%s\tFinish:%v\n\tData:[%s]", f.BaseFrame, f.BaseStreamLevelFrame, offset, length, f.Finish, f.Data)
}

func (f StreamFrame) genWire() (wire []byte, err error) {
	wireLen := 1 + qtype.QuicInt(f.StreamID).GetByteLen() + len(f.Data)
	if f.Type&0x04 == 0x04 {
		wireLen += f.Offset.GetByteLen()
	}
	if f.Type&0x02 == 0x02 {
		wireLen += f.Length.GetByteLen()
	}
	wire = make([]byte, wireLen)

	wire[0] = byte(f.Type)
	idx := f.StreamID.PutWire(wire[1:]) + 1
	if f.Type&0x04 == 0x04 {
		idx += f.Offset.PutWire(wire[idx:])
	}
	if f.Type&0x02 == 0x02 {
		idx += f.Length.PutWire(wire[idx:])
	}
	copy(wire[idx:], f.Data)
	return
}
