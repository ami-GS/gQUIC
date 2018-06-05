package quiclatest

import (
	"encoding/binary"

	"github.com/ami-GS/gQUIC/latest/qtype"
)

type Frame interface {
	GetWire() []byte
	genWire() ([]byte, error)
	GetType() FrameType
	GetWireSize() int
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
		"STOP_WAITING",
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

func ParseFrame(data []byte) (f Frame, idx int, err error) {
	if data[0] > 0x17 {
		// TODO: error needed
		return nil, 0, err
	}
	if data[0]&StreamFrameTypeCommon == StreamFrameTypeCommon {
		return FrameParserMap[StreamFrameTypeCommon](data)
	}
	return FrameParserMap[FrameType(data[0])](data)
}

func ParseFrames(data []byte) (fs []Frame, idx int, err error) {
	// TODO: or call parallel?
	for idx < len(data) {
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
	rLen, err := qtype.NewQuicInt(uint64(len(reason)))
	if err != nil {
		// error
	}
	f := &ConnectionCloseFrame{
		BaseFrame:    NewBaseFrame(ConnectionCloseFrameType),
		ErrorCode:    errorCode,
		ReasonLength: rLen,
		Reason:       reason,
	}
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseConnectionCloseFrame(data []byte) (Frame, int, error) {
	var err error
	f := &ConnectionCloseFrame{
		BaseFrame: NewBaseFrame(ConnectionCloseFrameType),
	}
	idx := 1
	f.ErrorCode = qtype.TransportError(binary.BigEndian.Uint16(data[idx:]))
	// TODO: check whether the code exists
	idx += 2
	f.ReasonLength, err = qtype.ParseQuicInt(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	idx += f.ReasonLength.ByteLen
	f.Reason = string(data[idx : idx+int(f.ReasonLength.GetValue())])
	idx += int(f.ReasonLength.GetValue())
	f.wire = data[:idx]

	return f, idx, nil
}

func (f ConnectionCloseFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 3+f.ReasonLength.ByteLen+len(f.Reason))
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
	rLen, err := qtype.NewQuicInt(uint64(len(reason)))
	if err != nil {
		// error
	}
	f := &ApplicationCloseFrame{
		BaseFrame:    NewBaseFrame(ApplicationCloseFrameType),
		ErrorCode:    errorCode,
		ReasonLength: rLen,
		Reason:       reason,
	}
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseApplicationCloseFrame(data []byte) (Frame, int, error) {
	var err error
	f := &ApplicationCloseFrame{
		BaseFrame: NewBaseFrame(ApplicationCloseFrameType),
	}
	idx := 1
	f.ErrorCode = qtype.ApplicationError(binary.BigEndian.Uint16(data[idx:]))
	// TODO: check whether the code exists
	idx += 2
	f.ReasonLength, err = qtype.ParseQuicInt(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	idx += f.ReasonLength.ByteLen
	f.Reason = string(data[idx : idx+int(f.ReasonLength.GetValue())])
	idx += int(f.ReasonLength.GetValue())
	f.wire = data[:idx]

	return f, idx, nil
}

func (f ApplicationCloseFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 3+f.ReasonLength.ByteLen+len(f.Reason))
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
	StreamID    qtype.StreamID
	ErrorCode   qtype.ApplicationError
	FinalOffset qtype.QuicInt
}

func NewRstStreamFrame(streamID uint64, errorCode qtype.ApplicationError, offset uint64) *RstStreamFrame {
	sid, err := qtype.NewQuicInt(streamID)
	if err != nil {
		// error
	}
	ofst, err := qtype.NewQuicInt(offset)
	if err != nil {
		// error
	}
	f := &RstStreamFrame{
		BaseFrame:   NewBaseFrame(RstStreamFrameType),
		StreamID:    qtype.StreamID(sid),
		ErrorCode:   errorCode,
		FinalOffset: ofst,
	}
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseRstStreamFrame(data []byte) (Frame, int, error) {
	idx := 1
	frame := &RstStreamFrame{
		BaseFrame: NewBaseFrame(RstStreamFrameType),
	}
	// TODO: bellow is not cool
	sid, err := qtype.ParseQuicInt(data[idx:])
	frame.StreamID = qtype.StreamID(sid)
	if err != nil {
		return nil, 0, err
	}
	idx += frame.StreamID.ByteLen
	frame.ErrorCode = qtype.ApplicationError(binary.BigEndian.Uint16(data[idx:]))
	idx += 2
	frame.FinalOffset, err = qtype.ParseQuicInt(data[idx:])
	idx += frame.FinalOffset.ByteLen
	frame.wire = data[:idx]

	return frame, idx, nil
}

func (f RstStreamFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 1+f.StreamID.ByteLen+2+f.FinalOffset.ByteLen)
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

func NewMaxDataFrame(val uint64) *MaxDataFrame {
	data, err := qtype.NewQuicInt(val)
	if err != nil {
		// error
	}
	f := &MaxDataFrame{
		BaseFrame: NewBaseFrame(MaxDataFrameType),
		Data:      data,
	}
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseMaxDataFrame(data []byte) (Frame, int, error) {
	var err error
	f := &MaxDataFrame{
		BaseFrame: NewBaseFrame(MaxDataFrameType),
	}
	f.Data, err = qtype.ParseQuicInt(data)
	if err != nil {
		return nil, 0, err
	}
	f.wire = data[:1+f.Data.ByteLen]

	return f, 1 + f.Data.ByteLen, nil
}

func (f MaxDataFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 1+f.Data.ByteLen)
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
	StreamID qtype.StreamID
	Data     qtype.QuicInt
}

func NewMaxStreamDataFrame(streamID uint64, val uint64) *MaxStreamDataFrame {
	sid, err := qtype.NewQuicInt(streamID)
	if err != nil {
		//error
	}
	data, err := qtype.NewQuicInt(val)
	if err != nil {
		// error
	}
	f := &MaxStreamDataFrame{
		BaseFrame: NewBaseFrame(MaxStreamDataFrameType),
		StreamID:  qtype.StreamID(sid),
		Data:      data,
	}
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseMaxStreamDataFrame(data []byte) (Frame, int, error) {
	var err error
	f := &MaxStreamDataFrame{
		BaseFrame: NewBaseFrame(MaxStreamDataFrameType),
	}
	sid, _ := qtype.ParseQuicInt(data[1:])
	f.StreamID = qtype.StreamID(sid)
	f.Data, err = qtype.ParseQuicInt(data[1+f.StreamID.ByteLen:])
	if err != nil {
		return nil, 0, err
	}
	f.wire = data[:1+f.StreamID.ByteLen+f.Data.ByteLen]
	return f, 1 + f.StreamID.ByteLen + f.Data.ByteLen, nil
}

func (f MaxStreamDataFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 1+f.StreamID.ByteLen+f.Data.ByteLen)
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
	StreamID qtype.StreamID
}

func NewMaxStreamIDFrame(streamID uint64) *MaxStreamIDFrame {
	sid, err := qtype.NewQuicInt(streamID)
	if err != nil {
		// error
	}
	f := &MaxStreamIDFrame{
		BaseFrame: NewBaseFrame(MaxStreamIDFrameType),
		StreamID:  qtype.StreamID(sid),
	}
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseMaxStreamIDFrame(data []byte) (Frame, int, error) {
	f := &MaxStreamIDFrame{
		BaseFrame: NewBaseFrame(MaxStreamIDFrameType),
	}
	sid, err := qtype.ParseQuicInt(data[1:])
	f.StreamID = qtype.StreamID(sid)
	if err != nil {
		return nil, 0, err
	}
	f.wire = data[:1+f.StreamID.ByteLen]
	return f, 1 + f.StreamID.ByteLen, nil
}

func (f MaxStreamIDFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 1+f.StreamID.ByteLen)
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

func NewBlockedFrame(offset uint64) *BlockedFrame {
	ofst, err := qtype.NewQuicInt(offset)
	if err != nil {
		// error
	}
	f := &BlockedFrame{
		BaseFrame: NewBaseFrame(BlockedFrameType),
		Offset:    ofst,
	}
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseBlockedFrame(data []byte) (Frame, int, error) {
	var err error
	f := &BlockedFrame{
		BaseFrame: NewBaseFrame(BlockedFrameType),
	}
	f.Offset, err = qtype.ParseQuicInt(data[1:])
	if err != nil {
		return nil, 0, err
	}
	f.wire = data[:1+f.Offset.ByteLen]
	return f, 1 + f.Offset.ByteLen, nil
}

func (f BlockedFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 1+f.Offset.ByteLen)
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
	StreamID qtype.StreamID
	Offset   qtype.QuicInt
}

func NewStreamBlockedFrame(streamID uint64, val uint64) *StreamBlockedFrame {
	sid, err := qtype.NewQuicInt(streamID)
	if err != nil {
		//error
	}
	data, err := qtype.NewQuicInt(val)
	if err != nil {
		// error
	}
	f := &StreamBlockedFrame{
		BaseFrame: NewBaseFrame(StreamBlockedFrameType),
		StreamID:  qtype.StreamID(sid),
		Offset:    data,
	}
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseStreamBlockedFrame(data []byte) (Frame, int, error) {
	f := &StreamBlockedFrame{
		BaseFrame: NewBaseFrame(StreamBlockedFrameType),
	}
	sid, err := qtype.ParseQuicInt(data[1:])
	f.StreamID = qtype.StreamID(sid)
	if err != nil {
		return nil, 0, err
	}
	f.Offset, _ = qtype.ParseQuicInt(data[1+f.StreamID.ByteLen:])
	if err != nil {
		return nil, 0, err
	}
	f.wire = data[:1+f.StreamID.ByteLen+f.Offset.ByteLen]
	return f, 1 + f.StreamID.ByteLen + f.Offset.ByteLen, nil
}

func (f StreamBlockedFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 1+f.StreamID.ByteLen+f.Offset.ByteLen)
	wire[0] = byte(StreamBlockedFrameType)
	f.StreamID.PutWire(wire[1:])
	f.Offset.PutWire(wire[1+f.StreamID.ByteLen:])
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
	StreamID qtype.StreamID
}

func NewStreamIDBlockedFrame(streamID uint64) *StreamIDBlockedFrame {
	sid, err := qtype.NewQuicInt(streamID)
	if err != nil {
		// error
	}
	f := &StreamIDBlockedFrame{
		BaseFrame: NewBaseFrame(StreamIDBlockedFrameType),
		StreamID:  qtype.StreamID(sid),
	}
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseStreamIDBlockedFrame(data []byte) (Frame, int, error) {
	f := &StreamIDBlockedFrame{
		BaseFrame: NewBaseFrame(StreamIDBlockedFrameType),
	}
	sid, err := qtype.ParseQuicInt(data[1:])
	f.StreamID = qtype.StreamID(sid)
	if err != nil {
		return nil, 0, err
	}
	f.wire = data[:1+f.StreamID.ByteLen]
	return f, 1 + f.StreamID.ByteLen, nil
}

func (f StreamIDBlockedFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 1+f.StreamID.ByteLen)
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

func NewNewConnectionIDFrame(sequence uint64, length byte, connID qtype.ConnectionID, stateLessRstTkn [16]byte) *NewConnectionIDFrame {
	seq, err := qtype.NewQuicInt(sequence)
	if err != nil {
		//error
	}
	f := &NewConnectionIDFrame{
		BaseFrame:       NewBaseFrame(NewConnectionIDFrameType),
		Sequence:        seq,
		Length:          length,
		ConnID:          connID,
		StatelessRstTkn: stateLessRstTkn,
	}
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
	f.Sequence, err = qtype.ParseQuicInt(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	f.Length = data[idx+f.Sequence.ByteLen]
	if f.Length < 4 || 18 < f.Length {
		// TODO: PROTOCOL_VIOLATION
		return nil, 0, nil
	}
	idx += f.Sequence.ByteLen + 1
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

func (f NewConnectionIDFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, 18+len(f.ConnID)+f.Sequence.ByteLen)
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
	StreamID  qtype.StreamID
	ErrorCode qtype.ApplicationError
}

func NewStopSendingFrame(streamID uint64, errCode qtype.ApplicationError) *StopSendingFrame {
	sid, err := qtype.NewQuicInt(streamID)
	if err != nil {
		// error
	}
	f := &StopSendingFrame{
		BaseFrame: NewBaseFrame(StopSendingFrameType),
		StreamID:  qtype.StreamID(sid),
		ErrorCode: errCode,
	}
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseStopSendingFrame(data []byte) (Frame, int, error) {
	f := &StopSendingFrame{
		BaseFrame: NewBaseFrame(StopSendingFrameType),
	}
	sid, err := qtype.ParseQuicInt(data[1:])
	f.StreamID = qtype.StreamID(sid)
	if err != nil {
		return nil, 0, err
	}
	f.ErrorCode = qtype.ApplicationError(binary.BigEndian.Uint16(data[1+f.StreamID.ByteLen:]))
	f.wire = data[:f.StreamID.ByteLen+3]
	return f, f.StreamID.ByteLen + 3, nil
}

func (f StopSendingFrame) genWire() (wire []byte, err error) {
	wire = make([]byte, f.StreamID.ByteLen+3)
	wire[0] = byte(StopSendingFrameType)
	f.StreamID.PutWire(wire[1:])
	binary.BigEndian.PutUint16(wire[1+f.StreamID.ByteLen:], uint16(f.ErrorCode))
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
	AckBlock qtype.QuicInt
	Gap      qtype.QuicInt
}

func NewAckBlock(ackBlock, gap uint64) *AckBlock {
	blk, err := qtype.NewQuicInt(ackBlock)
	if err != nil {
		return nil
	}
	gp, err := qtype.NewQuicInt(gap)
	if err != nil {
		return nil
	}

	return &AckBlock{
		AckBlock: blk,
		Gap:      gp,
	}
}

type AckFrame struct {
	*BaseFrame
	LargestAcked  qtype.QuicInt
	AckDelay      qtype.QuicInt
	AckBlockCount qtype.QuicInt
	AckBlocks     []AckBlock
}

func NewAckFrame(lAcked, ackDelay uint64, ackBlocks []AckBlock) *AckFrame {
	lakd, err := qtype.NewQuicInt(lAcked)
	if err != nil {
		// err
	}
	acdly, err := qtype.NewQuicInt(ackDelay)
	if err != nil {
		//
	}
	if ackBlocks == nil {
		return nil
	}

	acbc, err := qtype.NewQuicInt(uint64(len(ackBlocks) - 1))
	if err != nil {
		//
	}
	f := &AckFrame{
		BaseFrame:     NewBaseFrame(AckFrameType),
		LargestAcked:  lakd,
		AckDelay:      acdly,
		AckBlockCount: acbc,
		AckBlocks:     ackBlocks,
	}
	f.wire, err = f.genWire()
	if err != nil {
		// error
	}
	return f
}

func ParseAckFrame(data []byte) (Frame, int, error) {
	var err error
	f := &AckFrame{
		BaseFrame: NewBaseFrame(AckFrameType),
	}
	idx := 1
	f.LargestAcked, err = qtype.ParseQuicInt(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	idx += f.LargestAcked.ByteLen
	f.AckDelay, err = qtype.ParseQuicInt(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	idx += f.AckDelay.ByteLen
	f.AckBlockCount, err = qtype.ParseQuicInt(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	idx += f.AckBlockCount.ByteLen
	f.AckBlocks = make([]AckBlock, 1+f.AckBlockCount.GetValue())

	block, err := qtype.ParseQuicInt(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	f.AckBlocks[0].AckBlock = block
	idx += block.ByteLen
	for i := uint64(1); i < f.AckBlockCount.GetValue(); i++ {
		gap, err := qtype.ParseQuicInt(data[idx:])
		if err != nil {
			return nil, 0, err
		}
		f.AckBlocks[i].Gap = gap
		idx += gap.ByteLen
		block, err = qtype.ParseQuicInt(data[idx:])
		if err != nil {
			return nil, 0, err
		}
		f.AckBlocks[i].AckBlock = block
		idx += block.ByteLen
	}
	f.wire = data[:idx]
	return f, idx, nil
}

func (f AckFrame) genWire() (wire []byte, err error) {
	blockByteLen := 0
	for _, v := range f.AckBlocks {
		blockByteLen += v.AckBlock.ByteLen + v.Gap.ByteLen
	}
	wire = make([]byte, 1+f.LargestAcked.ByteLen+f.AckDelay.ByteLen+f.AckBlockCount.ByteLen+blockByteLen)
	wire[0] = byte(AckFrameType)
	idx := f.LargestAcked.PutWire(wire[1:]) + 1
	idx += f.AckDelay.PutWire(wire[idx:])
	idx += f.AckBlockCount.PutWire(wire[idx:])

	idx += f.AckBlocks[0].AckBlock.PutWire(wire[idx:])
	for i := uint64(1); i < f.AckBlockCount.GetValue(); i++ {
		v := f.AckBlocks[i]
		idx += v.Gap.PutWire(wire[idx:])
		idx += v.AckBlock.PutWire(wire[idx:])
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
	StreamID qtype.StreamID
	Offset   *qtype.QuicInt
	Length   *qtype.QuicInt
	Finish   bool
	Data     []byte
}

func NewStreamFrame(streamID, offset uint64, offF, lenF, fin bool, data []byte) *StreamFrame {
	sid, err := qtype.NewQuicInt(streamID)
	if err != nil {
		// error
	}
	typeFlag := StreamFrameType

	ofst := (*qtype.QuicInt)(nil)
	if offF {
		typeFlag |= 0x04
		tmp, err := qtype.NewQuicInt(offset)
		if err != nil {
			// error
		}
		ofst = &tmp
	}
	lngth := (*qtype.QuicInt)(nil)
	if lenF {
		typeFlag |= 0x02
		length := uint64(0)
		if data != nil {
			length = uint64(len(data))
		}
		tmp, err := qtype.NewQuicInt(length)
		if err != nil {
			// error
		}
		lngth = &tmp
	}
	if fin {
		typeFlag |= 0x01
	}

	f := &StreamFrame{
		BaseFrame: NewBaseFrame(typeFlag),
		StreamID:  qtype.StreamID(sid),
		Offset:    ofst,
		Length:    lngth,
		Finish:    fin,
		Data:      data,
	}
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
		BaseFrame: NewBaseFrame(StreamFrameType | FrameType(flag)),
	}
	sid, err := qtype.ParseQuicInt(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	f.StreamID = qtype.StreamID(sid)
	idx += f.StreamID.ByteLen
	// OFF bit
	if flag&0x04 == 0x04 {
		f.Type |= 0x04
		tmp, err := qtype.ParseQuicInt(data[idx:])
		if err != nil {
			return nil, 0, err
		}
		f.Offset = &tmp
		idx += f.Offset.ByteLen
	}

	// LEN bit
	if flag&0x02 == 0x02 {
		f.Type |= 0x02
		tmp, err := qtype.ParseQuicInt(data[idx:])
		if err != nil {
			return nil, 0, err
		}
		f.Length = &tmp
		idx += f.Length.ByteLen
		f.Data = data[idx : uint64(idx)+f.Length.GetValue()]
		idx += int(f.Length.GetValue())
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

func (f StreamFrame) genWire() (wire []byte, err error) {
	wireLen := 1 + f.StreamID.ByteLen + len(f.Data)
	if f.Type&0x04 == 0x04 {
		wireLen += f.Offset.ByteLen
	}
	if f.Type&0x02 == 0x02 {
		wireLen += f.Length.ByteLen
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
