package quiclatest

import (
	"encoding/binary"

	"github.com/ami-GS/gQUIC/latest/qtype"
)

type Frame interface {
	GetWire() ([]byte, error)
	GetType() FrameType
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
	PathChallengeFrameType:    ParsePathChallenge,
	PathResponseFrameType:     ParsePathResponse,

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
	}
	return names[int(frameType)]
}

type BaseFrame struct {
	Type FrameType
}

func NewBaseFrame(frameType FrameType) *BaseFrame {
	return &BaseFrame{
		Type: frameType,
	}
}

func (f *BaseFrame) GetType() FrameType {
	return f.Type
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
		wire, err := frame.GetWire()
		if err != nil {
			return nil, err
		}
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
	ErrorCode    uint16
	ReasonLength *qtype.QuicInt
	Reason       string
}

func NewConnectionCloseFrame(errorCode uint16, reason string) *ConnectionCloseFrame {
	rLen, err := qtype.NewQuicInt(uint64(len(reason)))
	if err != nil {
		// error
	}
	return &ConnectionCloseFrame{
		BaseFrame:    NewBaseFrame(ConnectionCloseFrameType),
		ErrorCode:    errorCode,
		ReasonLength: rLen,
		Reason:       reason,
	}
}

func ParseConnectionCloseFrame(data []byte) (Frame, int, error) {
	var err error
	f := NewConnectionCloseFrame(0, "")
	idx := 1
	f.ErrorCode = binary.BigEndian.Uint16(data[idx:])
	// TODO: check whether the code exists
	idx += 2
	f.ReasonLength, err = qtype.ParseQuicInt(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	idx += f.ReasonLength.ByteLen
	f.Reason = string(data[idx : idx+int(f.ReasonLength.GetValue())])

	return f, idx + int(f.ReasonLength.GetValue()), nil
}

func (f *ConnectionCloseFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 3+f.ReasonLength.ByteLen+len(f.Reason))
	wire[0] = byte(ConnectionCloseFrameType)
	idx := 1
	binary.BigEndian.PutUint16(wire[idx:], f.ErrorCode)
	idx += 2
	f.ReasonLength.PutWire(wire[idx:])
	idx += f.ReasonLength.ByteLen
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
	ErrorCode    uint16
	ReasonLength *qtype.QuicInt
	Reason       string
}

func NewApplicationCloseFrame(errorCode uint16, reason string) *ApplicationCloseFrame {
	rLen, err := qtype.NewQuicInt(uint64(len(reason)))
	if err != nil {
		// error
	}
	return &ApplicationCloseFrame{
		BaseFrame:    NewBaseFrame(ApplicationCloseFrameType),
		ErrorCode:    errorCode,
		ReasonLength: rLen,
		Reason:       reason,
	}
}

func ParseApplicationCloseFrame(data []byte) (Frame, int, error) {
	var err error
	f := NewApplicationCloseFrame(0, "")
	idx := 1
	f.ErrorCode = binary.BigEndian.Uint16(data[idx:])
	// TODO: check whether the code exists
	idx += 2
	f.ReasonLength, err = qtype.ParseQuicInt(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	idx += f.ReasonLength.ByteLen
	f.Reason = string(data[idx : idx+int(f.ReasonLength.GetValue())])

	return f, idx + int(f.ReasonLength.GetValue()), nil
}

func (f *ApplicationCloseFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 3+f.ReasonLength.ByteLen+len(f.Reason))
	wire[0] = byte(ApplicationCloseFrameType)
	idx := 1
	binary.BigEndian.PutUint16(wire[idx:], f.ErrorCode)
	idx += 2
	f.ReasonLength.PutWire(wire[idx:])
	idx += f.ReasonLength.ByteLen
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
	StreamID    *qtype.QuicInt
	ErrorCode   uint16
	FinalOffset *qtype.QuicInt
}

func NewRstStreamFrame(streamID uint64, errorCode uint16, offset uint64) *RstStreamFrame {
	sid, err := qtype.NewQuicInt(streamID)
	if err != nil {
		// error
	}
	ofst, err := qtype.NewQuicInt(offset)
	if err != nil {
		// error
	}
	return &RstStreamFrame{
		BaseFrame:   NewBaseFrame(RstStreamFrameType),
		StreamID:    sid,
		ErrorCode:   errorCode,
		FinalOffset: ofst,
	}
}
func ParseRstStreamFrame(data []byte) (Frame, int, error) {
	var err error
	idx := 1
	frame := NewRstStreamFrame(0, 0, 0)
	// TODO: bellow is not cool
	frame.StreamID, err = qtype.ParseQuicInt(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	idx += frame.StreamID.ByteLen
	frame.ErrorCode = binary.BigEndian.Uint16(data[idx:])
	idx += 2
	frame.FinalOffset, err = qtype.ParseQuicInt(data[idx:])
	return frame, idx + frame.FinalOffset.ByteLen, nil
}

func (f *RstStreamFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 1+f.StreamID.ByteLen+2+f.FinalOffset.ByteLen)
	wire[0] = byte(RstStreamFrameType)
	idx := 1
	f.StreamID.PutWire(wire[idx:])
	idx += f.StreamID.ByteLen
	binary.BigEndian.PutUint16(wire[idx:], f.ErrorCode)
	idx += 2
	f.FinalOffset.PutWire(wire[idx:])
	idx += f.FinalOffset.ByteLen
	return wire, nil
}

type PaddingFrame struct {
	*BaseFrame
}

func NewPaddingFrame() *PaddingFrame {
	return &PaddingFrame{
		BaseFrame: NewBaseFrame(PaddingFrameType),
	}
}

func ParsePaddingFrame(data []byte) (Frame, int, error) {
	frame := NewPaddingFrame()
	if len(data) != 0 {
		// TODO: padding should have flag 0x00 only
		return nil, 0, nil
	}
	return frame, len(data), nil
}
func (f *PaddingFrame) GetWire() (wire []byte, err error) {
	return []byte{0x00}, nil
}

type PingFrame struct {
	*BaseFrame
}

func NewPingFrame() *PingFrame {
	return &PingFrame{
		BaseFrame: NewBaseFrame(PingFrameType),
	}
}

func ParsePingFrame(data []byte) (Frame, int, error) {
	return NewPingFrame(), 1, nil // only header
}

func (f *PingFrame) GetWire() (wire []byte, err error) {
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
	Data *qtype.QuicInt
}

func NewMaxDataFrame(val uint64) *MaxDataFrame {
	data, err := qtype.NewQuicInt(val)
	if err != nil {
		// error
	}
	return &MaxDataFrame{
		BaseFrame: NewBaseFrame(MaxDataFrameType),
		Data:      data,
	}
}

func ParseMaxDataFrame(data []byte) (Frame, int, error) {
	var err error
	f := NewMaxDataFrame(0)
	f.Data, err = qtype.ParseQuicInt(data)
	if err != nil {
		return nil, 0, err
	}
	return f, 1 + f.Data.ByteLen, nil
}

func (f *MaxDataFrame) GetWire() (wire []byte, err error) {
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
	StreamID *qtype.QuicInt
	Data     *qtype.QuicInt
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
	return &MaxStreamDataFrame{
		BaseFrame: NewBaseFrame(MaxStreamDataFrameType),
		StreamID:  sid,
		Data:      data,
	}
}

func ParseMaxStreamDataFrame(data []byte) (Frame, int, error) {
	var err error
	f := NewMaxStreamDataFrame(0, 0)
	f.StreamID, _ = qtype.ParseQuicInt(data[1:])
	f.Data, err = qtype.ParseQuicInt(data[1+f.StreamID.ByteLen:])
	if err != nil {
		return nil, 0, err
	}
	return f, 1 + f.StreamID.ByteLen + f.Data.ByteLen, nil
}

func (f *MaxStreamDataFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 1+f.StreamID.ByteLen+f.Data.ByteLen)
	wire[0] = byte(MaxStreamDataFrameType)
	f.StreamID.PutWire(wire)
	f.Data.PutWire(wire[f.StreamID.ByteLen:])
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
	StreamID *qtype.QuicInt
}

func NewMaxStreamIDFrame(streamID uint64) *MaxStreamIDFrame {
	sid, err := qtype.NewQuicInt(streamID)
	if err != nil {
		// error
	}
	return &MaxStreamIDFrame{
		BaseFrame: NewBaseFrame(MaxStreamIDFrameType),
		StreamID:  sid,
	}
}

func ParseMaxStreamIDFrame(data []byte) (Frame, int, error) {
	var err error
	f := NewMaxStreamIDFrame(0)
	f.StreamID, err = qtype.ParseQuicInt(data[1:])
	if err != nil {
		return nil, 0, err
	}
	return f, 1 + f.StreamID.ByteLen, nil
}

func (f *MaxStreamIDFrame) GetWire() (wire []byte, err error) {
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
	Offset *qtype.QuicInt
}

func NewBlockedFrame(offset uint64) *BlockedFrame {
	ofst, err := qtype.NewQuicInt(offset)
	if err != nil {
		// error
	}
	return &BlockedFrame{
		BaseFrame: NewBaseFrame(BlockedFrameType),
		Offset:    ofst,
	}
}

func ParseBlockedFrame(data []byte) (Frame, int, error) {
	var err error
	f := NewBlockedFrame(0)
	f.Offset, err = qtype.ParseQuicInt(data[1:])
	if err != nil {
		return nil, 0, err
	}
	return f, 1 + f.Offset.ByteLen, nil
}

func (f *BlockedFrame) GetWire() (wire []byte, err error) {
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
	StreamID *qtype.QuicInt
	Offset   *qtype.QuicInt
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
	return &StreamBlockedFrame{
		BaseFrame: NewBaseFrame(StreamBlockedFrameType),
		StreamID:  sid,
		Offset:    data,
	}
}

func ParseStreamBlockedFrame(data []byte) (Frame, int, error) {
	var err error
	f := NewStreamBlockedFrame(0, 0)
	f.StreamID, err = qtype.ParseQuicInt(data[1:])
	if err != nil {
		return nil, 0, err
	}
	f.Offset, _ = qtype.ParseQuicInt(data[1+f.StreamID.ByteLen:])
	if err != nil {
		return nil, 0, err
	}
	return f, 1 + f.StreamID.ByteLen + f.Offset.ByteLen, nil
}

func (f *StreamBlockedFrame) GetWire() (wire []byte, err error) {
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
	StreamID *qtype.QuicInt
}

func NewStreamIDBlockedFrame(streamID uint64) *StreamIDBlockedFrame {
	sid, err := qtype.NewQuicInt(streamID)
	if err != nil {
		// error
	}
	return &StreamIDBlockedFrame{
		BaseFrame: NewBaseFrame(StreamIDBlockedFrameType),
		StreamID:  sid,
	}
}

func ParseStreamIDBlockedFrame(data []byte) (Frame, int, error) {
	var err error
	f := NewStreamIDBlockedFrame(0)
	f.StreamID, err = qtype.ParseQuicInt(data[1:])
	if err != nil {
		return nil, 0, err
	}
	return f, 1 + f.StreamID.ByteLen, nil
}

func (f *StreamIDBlockedFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 1+f.StreamID.ByteLen)
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
	Sequence        *qtype.QuicInt
	Length          byte
	ConnID          qtype.ConnectionID
	StatelessRstTkn [16]byte
}

func NewNewConnectionIDFrame(sequence uint64, length byte, connID qtype.ConnectionID, stateLessRstTkn [16]byte) *NewConnectionIDFrame {
	seq, err := qtype.NewQuicInt(sequence)
	if err != nil {
		//error
	}
	return &NewConnectionIDFrame{
		BaseFrame:       NewBaseFrame(NewConnectionIDFrameType),
		Sequence:        seq,
		Length:          length,
		ConnID:          connID,
		StatelessRstTkn: stateLessRstTkn,
	}
}

func ParseNewConnectionIDFrame(data []byte) (Frame, int, error) {
	var err error
	idx := 1
	f := NewNewConnectionIDFrame(0, 0, nil, [16]byte{})
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
	return f, idx + 16, nil
}

func (f *NewConnectionIDFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 18+len(f.ConnID)+f.Sequence.ByteLen)
	wire[0] = byte(NewConnectionIDFrameType)
	idx := 1
	f.Sequence.PutWire(wire)
	idx += f.Sequence.ByteLen
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
	StreamID  *qtype.QuicInt
	ErrorCode uint16
}

func NewStopSendingFrame(streamID uint64, errCode uint16) *StopSendingFrame {
	sid, err := qtype.NewQuicInt(streamID)
	if err != nil {
		// error
	}
	return &StopSendingFrame{
		BaseFrame: NewBaseFrame(StopSendingFrameType),
		StreamID:  sid,
		ErrorCode: errCode,
	}
}

func ParseStopSendingFrame(data []byte) (Frame, int, error) {
	var err error
	f := NewStopSendingFrame(0, 0)
	f.StreamID, err = qtype.ParseQuicInt(data[1:])
	if err != nil {
		return nil, 0, err
	}
	f.ErrorCode = binary.BigEndian.Uint16(data[1+f.StreamID.ByteLen:])
	return f, f.StreamID.ByteLen + 3, nil
}

func (f *StopSendingFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, f.StreamID.ByteLen+3)
	wire[0] = byte(StopSendingFrameType)
	f.StreamID.PutWire(wire[1:])
	binary.BigEndian.PutUint16(wire[1+f.StreamID.ByteLen:], f.ErrorCode)
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
	AckBlock *qtype.QuicInt
	Gap      *qtype.QuicInt
}

type AckFrame struct {
	*BaseFrame
	LargestAcked  *qtype.QuicInt
	AckDelay      *qtype.QuicInt
	AckBlockCount *qtype.QuicInt
	AckBlocks     []AckBlock
}

func NewAckFrame(lAcked, ackDelay, ackBlockCount uint64, ackBlocks []AckBlock) *AckFrame {
	lakd, err := qtype.NewQuicInt(lAcked)
	if err != nil {
		// err
	}
	acdly, err := qtype.NewQuicInt(ackDelay)
	if err != nil {
		//
	}
	acbc, err := qtype.NewQuicInt(ackBlockCount)
	if err != nil {
		//
	}
	return &AckFrame{
		BaseFrame:     NewBaseFrame(AckFrameType),
		LargestAcked:  lakd,
		AckDelay:      acdly,
		AckBlockCount: acbc,
		AckBlocks:     ackBlocks,
	}
}

func ParseAckFrame(data []byte) (Frame, int, error) {
	var err error
	f := NewAckFrame(0, 0, 0, nil)
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
	return f, idx, nil
}

func (f *AckFrame) GetWire() (wire []byte, err error) {
	blockByteLen := 0
	for _, v := range f.AckBlocks {
		blockByteLen += v.AckBlock.ByteLen + v.Gap.ByteLen
	}
	wire = make([]byte, 1+f.LargestAcked.ByteLen+f.AckDelay.ByteLen+f.AckBlockCount.ByteLen+blockByteLen)
	wire[0] = byte(AckFrameType)
	idx := 0
	f.LargestAcked.PutWire(wire)
	idx += f.LargestAcked.ByteLen
	f.AckDelay.PutWire(wire[idx:])
	idx += f.AckDelay.ByteLen
	f.AckBlockCount.PutWire(wire[idx:])
	idx += f.AckBlockCount.ByteLen

	f.AckBlocks[0].AckBlock.PutWire(wire[idx:])
	idx += f.AckBlocks[0].AckBlock.ByteLen
	for i := uint64(1); i < f.AckBlockCount.GetValue(); i++ {
		v := f.AckBlocks[i]
		v.Gap.PutWire(wire[idx:])
		idx += v.Gap.ByteLen
		v.AckBlock.PutWire(wire[idx:])
		idx += v.AckBlock.ByteLen
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

type PathChallenge struct {
	*BaseFrame
	Data [8]byte
}

func NewPathChallenge(data [8]byte) *PathChallenge {
	return &PathChallenge{
		BaseFrame: NewBaseFrame(PathChallengeFrameType),
		Data:      data,
	}
}

func ParsePathChallenge(data []byte) (Frame, int, error) {
	f := NewPathChallenge([8]byte{})
	copy(f.Data[:], data[1:9])
	return f, 9, nil
}

func (f *PathChallenge) GetWire() (wire []byte, err error) {
	wire = make([]byte, 9)
	wire[0] = byte(PathChallengeFrameType)
	copy(wire[1:], f.Data[:])
	return wire, nil
}

type PathResponse struct {
	*BaseFrame
	Data [8]byte
}

func NewPathResponse(data [8]byte) *PathResponse {
	return &PathResponse{
		BaseFrame: NewBaseFrame(PathResponseFrameType),
		Data:      data,
	}
}

func ParsePathResponse(data []byte) (Frame, int, error) {
	f := NewPathResponse([8]byte{})
	copy(f.Data[:], data[1:9])
	return f, 9, nil
}

func (f *PathResponse) GetWire() (wire []byte, err error) {
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
	StreamID *qtype.QuicInt
	Offset   *qtype.QuicInt
	Length   *qtype.QuicInt
	Finish   bool
	Data     []byte
}

func NewStreamFrame(streamID, offset, length uint64, fin bool, data []byte) *StreamFrame {
	sid, err := qtype.NewQuicInt(streamID)
	if err != nil {
		// error
	}
	// TODO: zero for no offset and length should not be appropriate
	ofst := (*qtype.QuicInt)(nil)
	if offset != 0 {
		ofst, err = qtype.NewQuicInt(offset)
		if err != nil {
			// error
		}
	}
	lngth := (*qtype.QuicInt)(nil)
	if length == 0 {
		lngth, err = qtype.NewQuicInt(length)
		if err != nil {
			// error
		}
	}
	return &StreamFrame{
		BaseFrame: NewBaseFrame(StreamFrameType),
		StreamID:  sid,
		Offset:    ofst,
		Length:    lngth,
		Finish:    fin,
		Data:      data,
	}
}

func ParseStreamFrame(data []byte) (Frame, int, error) {
	var err error
	idx := 1
	flag := data[0] ^ 0x07
	f := NewStreamFrame(0, 0, 0, false, nil)
	f.StreamID, err = qtype.ParseQuicInt(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	idx += f.StreamID.ByteLen
	// OFF bit
	if flag&0x04 == 0x04 {
		f.Offset, err = qtype.ParseQuicInt(data[idx:])
		if err != nil {
			return nil, 0, err
		}
		idx += f.Offset.ByteLen
	}

	// LEN bit
	if flag&0x02 == 0x02 {
		f.Length, err = qtype.ParseQuicInt(data[idx:])
		if err != nil {
			return nil, 0, err
		}
		idx += f.Length.ByteLen
	}
	f.Data = data[idx : uint64(idx)+f.Length.GetValue()]
	idx += int(f.Length.GetValue())

	// FIN bit
	if flag&0x01 == 0x01 {
		f.Finish = true
	}
	return f, idx, nil
}

func (f *StreamFrame) GetWire() (wire []byte, err error) {
	wireLen := 1 + f.StreamID.ByteLen + len(f.Data)
	flag := byte(StreamFrameType)
	if f.Offset != nil {
		wireLen += f.Offset.ByteLen
		flag |= 0x04
	}
	if f.Length != nil {
		wireLen += f.Length.ByteLen
		flag |= 0x02
	}
	if f.Finish {
		flag |= 0x01
	}
	wire = make([]byte, wireLen)
	wire[0] = flag
	idx := 1
	f.StreamID.PutWire(wire[idx:])
	idx += f.StreamID.ByteLen
	if flag&0x40 == 0x40 {
		f.Offset.PutWire(wire[idx:])
		idx += f.Offset.ByteLen
	}
	if flag&0x20 == 0x20 {
		f.Length.PutWire(wire[idx:])
		idx += f.Length.ByteLen
	}
	copy(wire[idx:], f.Data)
	return
}
