package quic

import (
	"encoding/binary"
	"fmt"
)

type FrameType uint8

const (
	PaddingFrameType FrameType = iota
	RstStreamFrameType
	ConnectionCloseFrameType
	GoAwayFrameType
	WindowUpdateFrameType
	BlockedFrameType
	StopWaitingFrameType
	PingFrameType
	StreamFrameType             = 0x80
	AckFrameType                = 0x40
	CongestionFeedbackFrameType = 0x20
)

func (frameType FrameType) String() string {
	names := []string{
		"PADDING",
		"RST_STREAM",
		"CONNECTION_CLOSE",
		"GOAWAY",
		"WINDOW_UPDATE",
		"BLOCKED",
		"STOP_WAITING",
		"PING",
	}
	switch frameType {
	case StreamFrameType:
		return "STREAM"
	case AckFrameType:
		return "ACK"
	case CongestionFeedbackFrameType:
		return "CONGESTION_FEEDBACK"
	default:
		return names[int(frameType)]
	}
}

type QuicErrorCode uint32

const (
	NO_ERROR QuicErrorCode = iota
	// TODO: write down Error code
	// the details are stil in progress?

)

type Frame interface {
	Parse(data []byte) (int, error)
	GetWire() ([]byte, error)
	SetPacket(*FramePacket)
	String() string
}

func NewFrame(fType FrameType) (frame Frame) {
	switch fType {
	case PaddingFrameType:
		frame = &PaddingFrame{}
	case RstStreamFrameType:
		frame = &RstStreamFrame{}
	case ConnectionCloseFrameType:
		frame = &ConnectionCloseFrame{}
	case GoAwayFrameType:
		frame = &GoAwayFrame{}
	case WindowUpdateFrameType:
		frame = &WindowUpdateFrame{}
	case BlockedFrameType:
		frame = &BlockedFrame{}
	case StopWaitingFrameType:
		frame = &StopWaitingFrame{}
	case PingFrameType:
		frame = &PingFrame{}
	default:
		if fType&StreamFrameType == StreamFrameType {
			frame = &StreamFrame{}
		} else if fType&AckFrameType == AckFrameType {
			frame = &AckFrame{}
		} else if fType&CongestionFeedbackFrameType == CongestionFeedbackFrameType {
			//frame = &CongestionFeedbackFrame{}
		}
	}
	return frame
}

/*
    0        1       ...               SLEN
+--------+--------+--------+--------+--------+
|Type (8)| Stream ID (8, 16, 24, or 32 bits) |
|        |    (Variable length SLEN bytes)   |
+--------+--------+--------+--------+--------+

  SLEN+1  SLEN+2     ...                                         SLEN+OLEN
+--------+--------+--------+--------+--------+--------+--------+--------+
|   Offset (0, 16, 24, 32, 40, 48, 56, or 64 bits) (variable length)    |
|                    (Variable length: OLEN  bytes)                     |
+--------+--------+--------+--------+--------+--------+--------+--------+

  SLEN+OLEN+1   SLEN+OLEN+2
+-------------+-------------+
| Data length (0 or 16 bits)|
|  Optional(maybe 0 bytes)  |
+------------+--------------+
*/

// TODO: is Data connected just after Data length?

type StreamFrame struct {
	*FramePacket
	Type     FrameType
	Settings byte
	Fin      bool
	StreamID uint32
	Offset   uint64
	Data     []byte
}

func NewStreamFrame(fin bool, streamID uint32, offset uint64, data []byte) *StreamFrame {
	var settings byte = 0
	if fin {
		settings |= 0x40
	}
	if len(data) != 0 { // should other argument be used?
		settings |= 0x20
	}

	// CHECK: are these bit length fixed?
	// 'ooo' bits
	switch {
	case offset == 0:
		settings |= 0x00
	case offset <= 0xffff:
		settings |= 0x04
	case offset <= 0xffffff:
		settings |= 0x08
	case offset <= 0xffffffff:
		settings |= 0x0c
	case offset <= 0xffffffffff:
		settings |= 0x10
	case offset <= 0xffffffffffff:
		settings |= 0x14
	case offset <= 0xffffffffffffff:
		settings |= 0x18
	case offset <= 0xffffffffffffffff:
		settings |= 0x1c
	}

	// 'ss' bits
	switch {
	case streamID <= 0xff:
		settings |= 0x00
	case streamID <= 0xffff:
		settings |= 0x01
	case streamID <= 0xffffff:
		settings |= 0x02
	case streamID <= 0xffffffff:
		settings |= 0x03
	}

	streamFrame := &StreamFrame{
		Type:     StreamFrameType,
		Settings: settings,
		Fin:      fin,
		StreamID: streamID,
		Offset:   offset,
		Data:     data,
	}
	return streamFrame
}

func (frame *StreamFrame) Parse(data []byte) (length int, err error) {
	frame.Type = StreamFrameType
	frame.Settings = data[0] & 0x7f
	if frame.Settings&0x40 == 0x40 {
		frame.Fin = true
		//TODO: fin
	}

	length = 1
	switch frame.Settings & 0x03 {
	case 0x00:
		frame.StreamID = uint32(data[1])
		length += 1
	case 0x01:
		frame.StreamID = uint32(data[1])<<8 | uint32(data[2])
		length += 2
	case 0x02:
		frame.StreamID = uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
		length += 3
	case 0x03:
		frame.StreamID = binary.BigEndian.Uint32(data[1:5])
		length += 4
	}

	switch frame.Settings & 0x1c {
	case 0x00:
		frame.Offset = 0
	case 0x04:
		frame.Offset = uint64(data[length])<<8 | uint64(data[length+1])
		length += 2
	case 0x08:
		frame.Offset = uint64(data[length])<<16 | uint64(data[length+1])<<8 | uint64(data[length+2])
		length += 3
	case 0x0c:
		for i := 0; i < 4; i++ {
			frame.Offset |= uint64(data[length+i]) << byte(8*(3-i))
		}
		length += 4
	case 0x10:
		for i := 0; i < 5; i++ {
			frame.Offset |= uint64(data[length+i]) << byte(8*(4-i))
		}
		length += 5
	case 0x14:
		for i := 0; i < 6; i++ {
			frame.Offset |= uint64(data[length+i]) << byte(8*(5-i))
		}
		length += 6
	case 0x18:
		for i := 0; i < 7; i++ {
			frame.Offset |= uint64(data[length+i]) << byte(8*(6-i))
		}
		length += 7
	case 0x1c:
		frame.Offset |= binary.BigEndian.Uint64(data[length:])
		length += 8
	}

	var dataLength uint16 // as is not contained. right?
	if frame.Settings&0x20 == 0x20 {
		dataLength = binary.BigEndian.Uint16(data[length:])
		length += 2
	}
	frame.Data = data[length : length+int(dataLength)]
	length += int(dataLength)

	return
}

func (frame *StreamFrame) GetWire() (wire []byte, err error) {
	// data length's length
	DLEN := int((frame.Settings & 0x20 >> 5) * 2)

	// streamID length
	SLEN := int((frame.Settings & 0x03) + 1)

	// offset length
	OLEN := int((frame.Settings & 0x1c >> 2))
	if OLEN > 0 {
		OLEN += 1
	}

	dataLength := len(frame.Data)
	wire = make([]byte, 1+DLEN+SLEN+OLEN+dataLength)
	wire[0] = byte(frame.Type) + frame.Settings
	index := 1

	for i := 0; i < SLEN; i++ {
		wire[index+i] = byte(frame.StreamID >> byte(8*(SLEN-i-1)))
	}
	index += SLEN

	for i := 0; i < OLEN; i++ {
		wire[index+i] = byte(frame.Offset >> byte(8*(OLEN-i-1)))
	}
	index += OLEN

	if DLEN > 0 {
		binary.BigEndian.PutUint16(wire[index:], uint16(dataLength))
		index += 2
	}

	for i := 0; i < dataLength; i++ {
		wire[index+i] = frame.Data[i]
	}

	return
}

func (frame *StreamFrame) String() (str string) {
	str = fmt.Sprintf("STREAM\n\tStreamID : %d, Offset : %d, DataLength : %d, Data: %v",
		frame.StreamID, frame.Offset, len(frame.Data), frame.Data)
	return str
}

func (frame *StreamFrame) SetPacket(packet *FramePacket) {
	frame.FramePacket = packet
}

/*
      0        1                           N
 +--------+--------+---------------------------------------------------+
 |Type (8)|Received|    Largest Observed (8, 16, 32, or 48 bits)       |
 |        |Entropy |                     (variable length)             |
 +--------+--------+---------------------------------------------------+
    N+1       N+2      N+3      N+4                   N+8
 +--------+--------+---------+--------+--------------------------------+
 |Largest Observed |   Num   | Delta  |  Time Since Largest Observed   |
 | Delta Time (16) |Timestamp|Largest |                                |
 |        |        |   (8)   |Observed|                                |
 +--------+--------+---------+--------+--------------------------------+
    N+9         N+11 - X
 +--------+------------------+
 | Delta  |       Time       |
 |Largest |  Since Previous  |
 |Observed|Timestamp (Repeat)|
 +--------+------------------+
     X                        X+1 - Y                           Y+1
 +--------+-------------------------------------------------+--------+
 | Number |    Missing Packet Sequence Number Delta         | Range  |
 | Ranges | (repeats Number Ranges times with Range Length) | Length |
 | (opt)  |                                                 |(Repeat)|
 +--------+-------------------------------------------------+--------+
     Y+2                       Y+3 - Z
 +--------+-----------------------------------------------------+
 | Number |       Revived Packet  (8, 16, 32, or 48 bits)       |
 | Revived|       Sequence Number (variable length)             |
 | (opt)  |         (repeats Number Revied times)               |
 +--------+-----------------------------------------------------+
*/

type AckFrame struct {
	*FramePacket
	Type                              FrameType
	Settings                          byte
	ReceivedEntropy                   byte
	LargestObserved                   uint64
	LargestObservedDeltaTime          uint16 // actual type is ufloat16
	NumTimestamp                      byte
	DeltaSinceLargestObserved         byte
	TimeSinceLargestObserved          uint32
	DeltaSincePreviousLargestObserved []byte
	TimeSincePreviousTimestamp        []uint16
	NumRanges                         byte
	MissingPacketSequenceNumberDelta  []uint64 //suspicious
	RangeLength                       []byte
	NumRevived                        byte
	RevivedPacketSequenceNumber       []uint64
}

func NewAckFrame(hasNACK, isTruncate bool, largestObserved, missingDelta uint64) *AckFrame {
	var settings byte = 0
	// 'n' bit
	if hasNACK {
		settings |= 0x20
	}
	// 't' bit
	if isTruncate {
		settings |= 0x10
	}

	// 'll' bits
	switch {
	case largestObserved <= 0xff:
		settings |= 0x00
	case largestObserved <= 0xffff:
		settings |= 0x04
	case largestObserved <= 0xffffff:
		settings |= 0x08
	case largestObserved <= 0xffffffff:
		settings |= 0x0c
	}

	// 'mm' bits
	switch {
	case missingDelta <= 0xff:
		settings |= 0x00
	case missingDelta <= 0xffff:
		settings |= 0x04
	case missingDelta <= 0xffffff:
		settings |= 0x08
	case missingDelta <= 0xffffffff:
		settings |= 0x0c
	}

	ackFrame := &AckFrame{
		Type:     AckFrameType,
		Settings: settings,
	}
	return ackFrame
}

func (frame *AckFrame) Parse(data []byte) (length int, err error) {
	frame.Type = AckFrameType
	frame.Settings = data[0] & 0x3f
	frame.ReceivedEntropy = data[1]
	length = 2
	lOLen := 0
	if frame.Settings&0x10 == 0x10 {
		// TODO:istruncate
	}
	switch frame.Settings & 0x0c {
	case 0x00:
		lOLen = 1
	case 0x04:
		lOLen = 2
	case 0x08:
		lOLen = 4
	case 0x0c:
		lOLen = 6
	}
	for i := 0; i < lOLen; i++ {
		frame.LargestObserved |= uint64(data[length]) << byte(8*(lOLen-i-1))
		length += 1
	}

	mPSeqNumDLen := 0
	switch frame.Settings & 0x03 {
	case 0x00:
		mPSeqNumDLen = 1
	case 0x01:
		mPSeqNumDLen = 2
	case 0x02:
		mPSeqNumDLen = 4
	case 0x03:
		mPSeqNumDLen = 6
	}

	length += lOLen
	frame.LargestObservedDeltaTime = binary.BigEndian.Uint16(data[length:])
	frame.NumTimestamp = data[length+2]
	frame.DeltaSinceLargestObserved = data[length+3]
	frame.TimeSinceLargestObserved = binary.BigEndian.Uint32(data[length+4:])
	length += 8

	frame.DeltaSincePreviousLargestObserved = make([]byte, frame.NumTimestamp)
	frame.TimeSincePreviousTimestamp = make([]uint16, frame.NumTimestamp)
	for i := 0; i < int(frame.NumTimestamp); i++ {
		frame.DeltaSincePreviousLargestObserved[i] = data[length]
		frame.TimeSincePreviousTimestamp[i] = binary.BigEndian.Uint16(data[length+1:])
		length += 3
	}
	if frame.Settings&0x20 == 0x20 {
		frame.NumRanges = data[length]
		length += 1
		frame.MissingPacketSequenceNumberDelta = make([]uint64, frame.NumRanges)
		frame.RangeLength = make([]byte, frame.NumRanges)
		for i := 0; i < int(frame.NumRanges); i++ {
			for j := 0; j < mPSeqNumDLen; j++ {
				frame.MissingPacketSequenceNumberDelta[i] |= uint64(data[length]) << byte(8*(mPSeqNumDLen-j-1))
				length += 1
			}
			frame.RangeLength[i] = data[length]
			length += 1
		}
		frame.NumRevived = data[length]
		length += 1
		frame.RevivedPacketSequenceNumber = make([]uint64, frame.NumRevived)
		for i := 0; i < int(frame.NumRevived); i++ {
			for j := 0; j < lOLen; j++ {
				frame.RevivedPacketSequenceNumber[i] |= uint64(data[length]) << byte(8*(lOLen-j-1))
				length += 1
			}
		}
	}

	return
}

func (frame *AckFrame) GetWire() (wire []byte, err error) {
	if frame.Settings&0x20 == 0x20 {
		// TODO:deal with truncated frame
	}

	lOLen := 0
	switch frame.Settings & 0x0c {
	case 0x00:
		lOLen = 1
	case 0x04:
		lOLen = 2
	case 0x08:
		lOLen = 4
	case 0x0c:
		lOLen = 6
	}

	mPSeqNumDLen := 0
	switch frame.Settings & 0x30 {
	case 0x00:
		mPSeqNumDLen = 1
	case 0x01:
		mPSeqNumDLen = 2
	case 0x02:
		mPSeqNumDLen = 4
	case 0x03:
		mPSeqNumDLen = 6
	}

	hasNACK := 0
	if frame.Settings&0x10 == 0x10 {
		hasNACK = 1
	}

	wire = make([]byte, 1+1+lOLen+2+1+1+4+int(frame.NumTimestamp)*3+hasNACK*2+int(frame.NumRanges)*(mPSeqNumDLen+1)+int(frame.NumRevived)*lOLen)
	wire[0] = byte(frame.Type) + frame.Settings
	wire[1] = frame.ReceivedEntropy
	length := 2
	for i := 0; i < lOLen; i++ {
		wire[i+length] = byte(frame.LargestObserved >> byte(8*(lOLen-i-1)))
	}
	length += lOLen
	binary.BigEndian.PutUint16(wire[length:], frame.LargestObservedDeltaTime)
	wire[length+2] = frame.NumTimestamp
	wire[length+3] = frame.DeltaSinceLargestObserved
	binary.BigEndian.PutUint32(wire[length+4:], frame.TimeSinceLargestObserved)
	length += 8
	for i := 0; i < int(frame.NumTimestamp); i++ {
		wire[length+i] = frame.DeltaSincePreviousLargestObserved[i]
		binary.BigEndian.PutUint16(wire[length+i+1:], frame.TimeSincePreviousTimestamp[i])
		length += 3
	}

	if hasNACK == 1 {
		wire[length] = frame.NumRanges
		length += 1
		for i := 0; i < int(frame.NumRanges); i++ {
			for j := 0; j < mPSeqNumDLen; j++ {
				wire[length+j] = byte(frame.MissingPacketSequenceNumberDelta[i] >> byte(8*(mPSeqNumDLen-j-1)))
			}
			wire[length+mPSeqNumDLen] = frame.RangeLength[i]
			length += 1
		}
		wire[length] = frame.NumRevived
		length += 1
		for i := 0; i < int(frame.NumRevived); i++ {
			for j := 0; j < lOLen; j++ {
				wire[length+j] = byte(frame.RevivedPacketSequenceNumber[i] >> byte(8*(lOLen-j-1)))
			}
			length += lOLen
		}
	}

	return
}

func (frame *AckFrame) String() (str string) {
	str = fmt.Sprintf("ACK\n\t")
	return str
}

func (frame *AckFrame) SetPacket(packet *FramePacket) {
	frame.FramePacket = packet
}

/*
      0        1        2        3         4        5        6      7
 +--------+--------+--------+--------+--------+--------+-------+-------+
 |Type (8)|Sent    |   Least unacked delta (8, 16, 32, or 48 bits)     |
 |        |Entropy |                       (variable length)           |
 +--------+--------+--------+--------+--------+--------+-------+-------+
*/

type StopWaitingFrame struct {
	*FramePacket
	Type              FrameType
	SentEntropy       byte
	LeastUnackedDelta uint64
}

func NewStopWaitingFrame(sentEntropy byte, leastUnackedDelta uint64) *StopWaitingFrame {
	stopWaitingFrame := &StopWaitingFrame{
		Type:              StopWaitingFrameType,
		SentEntropy:       sentEntropy,
		LeastUnackedDelta: leastUnackedDelta,
	}
	return stopWaitingFrame
}

func (frame *StopWaitingFrame) Parse(data []byte) (length int, err error) {
	frame.Type = FrameType(data[0])
	frame.SentEntropy = data[1]

	// the same length as the packet header's sequence number
	switch frame.PublicFlags & SEQUENCE_NUMBER_LENGTH_MASK {
	case SEQUENCE_NUMBER_LENGTH_6:
		length = 6
	case SEQUENCE_NUMBER_LENGTH_4:
		length = 4
	case SEQUENCE_NUMBER_LENGTH_2:
		length = 2
	case SEQUENCE_NUMBER_LENGTH_1:
		length = 1
	}

	for i := 0; i < length; i++ {
		frame.LeastUnackedDelta |= uint64(data[2+i] << byte(8*(length-i-1)))
	}

	return length + 2, err
}

func (frame *StopWaitingFrame) GetWire() (wire []byte, err error) {
	// shold here be functionized?
	length := 1
	switch frame.PublicFlags & SEQUENCE_NUMBER_LENGTH_MASK {
	case SEQUENCE_NUMBER_LENGTH_6:
		length = 6
	case SEQUENCE_NUMBER_LENGTH_4:
		length = 4
	case SEQUENCE_NUMBER_LENGTH_2:
		length = 2
	case SEQUENCE_NUMBER_LENGTH_1:
		length = 1
	}

	wire = make([]byte, 2+length)
	wire[0] = byte(frame.Type)
	wire[1] = frame.SentEntropy

	for i := 0; i < length; i++ {
		wire[2+i] = byte(frame.LeastUnackedDelta >> byte(8*(length-i-1)))
	}

	return
}

func (frame *StopWaitingFrame) String() (str string) {
	str = fmt.Sprintf("STOP WAITING\n\tSent Entropy : %d, Least unacked delta : %d",
		frame.SentEntropy, frame.LeastUnackedDelta)
	return str
}

func (frame *StopWaitingFrame) SetPacket(packet *FramePacket) {
	frame.FramePacket = packet
}

/*
     0         1                 4        5                 12
 +--------+--------+-- ... --+-------+--------+-- ... --+-------+
 |Type(8) |    Stream ID (32 bits)   |  Byte offset (64 bits)   |
 +--------+--------+-- ... --+-------+--------+-- ... --+-------+
*/

type WindowUpdateFrame struct {
	*FramePacket
	Type     FrameType
	StreamID uint32
	Offset   uint64
}

func NewWindowUpdateFrame(streamID uint32, offset uint64) *WindowUpdateFrame {
	windowUpdateFrame := &WindowUpdateFrame{
		Type:     WindowUpdateFrameType,
		StreamID: streamID,
		Offset:   offset,
	}
	return windowUpdateFrame
}

func (frame *WindowUpdateFrame) Parse(data []byte) (length int, err error) {
	length = 13
	frame.Type = FrameType(data[0])
	frame.StreamID = binary.BigEndian.Uint32(data[1:])
	frame.Offset = binary.BigEndian.Uint64(data[5:])
	return
}

func (frame *WindowUpdateFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 13)
	wire[0] = byte(frame.Type)
	binary.BigEndian.PutUint32(wire[1:], frame.StreamID)
	binary.BigEndian.PutUint64(wire[5:], frame.Offset)

	return
}

func (frame *WindowUpdateFrame) String() (str string) {
	str = fmt.Sprintf("WINDOW UPDATE\n\tStreamID : %d, Offset : %d",
		frame.StreamID, frame.Offset)
	return str
}

func (frame *WindowUpdateFrame) SetPacket(packet *FramePacket) {
	frame.FramePacket = packet
}

/*
      0        1        2        3         4
 +--------+--------+--------+--------+--------+
 |Type(8) |          Stream ID (32 bits)      |
 +--------+--------+--------+--------+--------+
*/
type BlockedFrame struct {
	*FramePacket
	Type     FrameType
	StreamID uint32
}

func NewBlockedFrame(streamID uint32) *BlockedFrame {
	blockedFrame := &BlockedFrame{
		Type:     BlockedFrameType,
		StreamID: streamID,
	}
	return blockedFrame
}

func (frame *BlockedFrame) Parse(data []byte) (length int, err error) {
	length = 5
	frame.Type = FrameType(data[0])
	frame.StreamID = binary.BigEndian.Uint32(data[1:])
	return
}

func (frame *BlockedFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 5)
	wire[0] = byte(frame.Type)
	binary.BigEndian.PutUint32(wire[1:], frame.StreamID)

	return
}

func (frame *BlockedFrame) String() (str string) {
	str = fmt.Sprintf("BLOCKED\n\tStreamID %d", frame.StreamID)
	return str
}

func (frame *BlockedFrame) SetPacket(packet *FramePacket) {
	frame.FramePacket = packet
}

// CongestionFeedback
type PaddingFrame struct {
	*FramePacket
	Type FrameType
}

func NewPaddingFrame() *PaddingFrame {
	paddingFrame := &PaddingFrame{
		Type: PaddingFrameType,
	}
	return paddingFrame
}

func (frame *PaddingFrame) Parse(data []byte) (length int, err error) {
	length = len(data)
	return
}

func (frame *PaddingFrame) GetWire() (wire []byte, err error) {
	// Frame Type is 0x00, no need to substitute
	wire = make([]byte, frame.RestSize)
	return
}
func (frame *PaddingFrame) String() (str string) {
	str = "PADDING\n\t"
	return str
}

func (frame *PaddingFrame) SetPacket(packet *FramePacket) {
	frame.FramePacket = packet
}

/*
     0        1            4      5              12     8             16
+-------+--------+-- ... ----+--------+-- ... ------+-------+-- ... ------+
|Type(8)| StreamID (32 bits) | Byte offset (64 bits)| Error code (32 bits)|
+-------+--------+-- ... ----+--------+-- ... ------+-------+-- ... ------+
*/

type RstStreamFrame struct {
	*FramePacket
	Type      FrameType
	StreamID  uint32
	Offset    uint64
	ErrorCode QuicErrorCode
}

func NewRstStreamFrame(streamID uint32, offset uint64, errorCode QuicErrorCode) *RstStreamFrame {
	rstStreamFrame := &RstStreamFrame{
		Type:      RstStreamFrameType,
		StreamID:  streamID,
		Offset:    offset,
		ErrorCode: errorCode,
	}
	return rstStreamFrame
}

func (frame *RstStreamFrame) Parse(data []byte) (length int, err error) {
	length = 17
	frame.Type = FrameType(data[0])
	frame.StreamID = binary.BigEndian.Uint32(data[1:])
	frame.Offset = binary.BigEndian.Uint64(data[5:])
	frame.ErrorCode = QuicErrorCode(binary.BigEndian.Uint32(data[13:]))
	return
}

func (frame *RstStreamFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 17)
	wire[0] = byte(frame.Type)
	binary.BigEndian.PutUint32(wire[1:], frame.StreamID)
	binary.BigEndian.PutUint64(wire[5:], frame.Offset)
	binary.BigEndian.PutUint32(wire[13:], uint32(frame.ErrorCode))
	return
}

func (frame *RstStreamFrame) String() (str string) {
	str = fmt.Sprintf("RST STREAM\n\tStreamID : %d, Offset : %d, Error code : %d",
		frame.StreamID, frame.Offset, frame.ErrorCode) // TODO: Error Code should be string
	return str
}

func (frame *RstStreamFrame) SetPacket(packet *FramePacket) {
	frame.FramePacket = packet
}

type PingFrame struct {
	*FramePacket
	Type FrameType
}

func NewPingFrame() *PingFrame {
	pingFrame := &PingFrame{
		Type: PingFrameType,
	}
	return pingFrame
}

func (frame *PingFrame) Parse(data []byte) (length int, err error) {
	length = 1
	frame.Type = FrameType(data[0])
	return
}
func (frame *PingFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 1)
	wire[0] = byte(frame.Type)
	return
}

func (frame *PingFrame) String() (str string) {
	str = fmt.Sprintf("PING\n\t")
	return str
}

func (frame *PingFrame) SetPacket(packet *FramePacket) {
	frame.FramePacket = packet
}

/*
        0        1             4        5        6       7
   +--------+--------+-- ... -----+--------+--------+--------+----- ...
   |Type(8) | Error code (32 bits)| Reason phrase   |  Reason phrase
   |        |                     | length (16 bits)|(variable length)
   +--------+--------+-- ... -----+--------+--------+--------+----- ...
*/

type ConnectionCloseFrame struct {
	*FramePacket
	Type               FrameType
	ErrorCode          QuicErrorCode
	ReasonPhraseLength uint16
	ReasonPhrase       string
}

func NewConnectionCloseFrame(errorCode QuicErrorCode, reasonPhrase string) *ConnectionCloseFrame {

	connectionCloseFrame := &ConnectionCloseFrame{
		Type:               ConnectionCloseFrameType,
		ErrorCode:          errorCode,
		ReasonPhraseLength: uint16(len(reasonPhrase)), // TODO: cut if the length is over uint16
		ReasonPhrase:       reasonPhrase,
	}
	return connectionCloseFrame
}

func (frame *ConnectionCloseFrame) Parse(data []byte) (length int, err error) {
	frame.Type = FrameType(data[0])
	frame.ErrorCode = QuicErrorCode(binary.BigEndian.Uint32(data[1:]))
	frame.ReasonPhraseLength = binary.BigEndian.Uint16(data[5:])
	frame.ReasonPhrase = string(data[7 : 7+frame.ReasonPhraseLength])
	length = 7 + int(frame.ReasonPhraseLength)
	return
}

func (frame *ConnectionCloseFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 7+frame.ReasonPhraseLength)
	wire[0] = byte(frame.Type)
	binary.BigEndian.PutUint32(wire[1:], uint32(frame.ErrorCode))
	binary.BigEndian.PutUint16(wire[5:], frame.ReasonPhraseLength)

	byteString := []byte(frame.ReasonPhrase)
	for i, v := range byteString {
		wire[7+i] = v
	}
	return
}

func (frame *ConnectionCloseFrame) String() (str string) {
	str = fmt.Sprintf("CONNECTION CLOSE\n\tError code : %d, Reason length : %d\nReason : %s",
		frame.ErrorCode, frame.ReasonPhraseLength, frame.ReasonPhrase)
	return str
}

func (frame *ConnectionCloseFrame) SetPacket(packet *FramePacket) {
	frame.FramePacket = packet
}

/*
        0        1             4      5       6       7      8
   +--------+--------+-- ... -----+-------+-------+-------+------+
   |Type(8) | Error code (32 bits)| Last Good Stream ID (32 bits)| ->
   +--------+--------+-- ... -----+-------+-------+-------+------+
         9        10       11
   +--------+--------+--------+----- ...
   | Reason phrase   |  Reason phrase
   | length (16 bits)|(variable length)
   +--------+--------+--------+----- ...
*/

type GoAwayFrame struct {
	*FramePacket
	Type               FrameType
	ErrorCode          QuicErrorCode
	LastGoodStreamID   uint32
	ReasonPhraseLength uint16
	ReasonPhrase       string
}

func NewGoAwayFrame(errorCode QuicErrorCode, lastGoodStreamID uint32, reasonPhrase string) *GoAwayFrame {
	goAwayFrame := &GoAwayFrame{
		Type:               GoAwayFrameType,
		ErrorCode:          errorCode,
		LastGoodStreamID:   lastGoodStreamID,
		ReasonPhraseLength: uint16(len(reasonPhrase)),
		ReasonPhrase:       reasonPhrase,
	}
	return goAwayFrame
}

func (frame *GoAwayFrame) Parse(data []byte) (length int, err error) {
	frame.Type = FrameType(data[0])
	frame.ErrorCode = QuicErrorCode(binary.BigEndian.Uint32(data[1:]))
	frame.LastGoodStreamID = binary.BigEndian.Uint32(data[5:])
	frame.ReasonPhraseLength = binary.BigEndian.Uint16(data[9:])
	frame.ReasonPhrase = string(data[11 : 11+frame.ReasonPhraseLength])
	length = 11 + int(frame.ReasonPhraseLength)
	return
}

func (frame *GoAwayFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 11+frame.ReasonPhraseLength)
	wire[0] = byte(frame.Type)
	binary.BigEndian.PutUint32(wire[1:], uint32(frame.ErrorCode))
	binary.BigEndian.PutUint32(wire[5:], frame.LastGoodStreamID)
	binary.BigEndian.PutUint16(wire[9:], frame.ReasonPhraseLength)

	byteString := []byte(frame.ReasonPhrase)
	for i, v := range byteString {
		wire[11+i] = v
	}

	return
}

func (frame *GoAwayFrame) String() (str string) {
	str = fmt.Sprintf("GOAWAY\n\tError code : %d, LastGoodStreamID : %d, Reason length : %d\nReason : %s",
		frame.ErrorCode, frame.LastGoodStreamID, frame.ReasonPhraseLength, frame.ReasonPhrase)
	return str
}
func (frame *GoAwayFrame) SetPacket(packet *FramePacket) {
	frame.FramePacket = packet
}
