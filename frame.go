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

type Frame interface {
	GetWire() ([]byte, error)
	String() string
}

type FrameParser func(fp *FramePacket, data []byte) (Frame, int)

var FrameParserMap = map[FrameType]FrameParser{
	PaddingFrameType:            ParsePaddingFrame,
	RstStreamFrameType:          ParseRstStreamFrame,
	ConnectionCloseFrameType:    ParseConnectionCloseFrame,
	GoAwayFrameType:             ParseGoAwayFrame,
	WindowUpdateFrameType:       ParseWindowUpdateFrame,
	BlockedFrameType:            ParseBlockedFrame,
	StopWaitingFrameType:        ParseStopWaitingFrame,
	PingFrameType:               ParsePingFrame,
	StreamFrameType:             ParseStreamFrame,
	AckFrameType:                ParseAckFrame,
	CongestionFeedbackFrameType: ParseCongestionFeedbackFrame,
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

func ParseStreamFrame(fp *FramePacket, data []byte) (Frame, int) {
	frame := &StreamFrame{
		FramePacket: fp,
		Type:        StreamFrameType,
		Settings:    data[0] & 0x7f,
	}
	if frame.Settings&0x40 == 0x40 {
		frame.Fin = true
		//TODO: fin
	}

	length := 1
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

	return frame, length
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

	copy(wire[index:], frame.Data)

	return
}

func (frame *StreamFrame) String() (str string) {
	str = fmt.Sprintf("STREAM\n\t\tStreamID : %d, Offset : %d, DataLength : %d, Data: %v",
		frame.StreamID, frame.Offset, len(frame.Data), frame.Data)
	return str
}

/*
     0                            1  => N                     N+1 => A(aka N + 3)
+---------+-------------------------------------------------+--------+--------+
|   Type  |                   Largest Acked                 |  Largest Acked  |
|   (8)   |    (8, 16, 32, or 48 bits, determined by ll)    | Delta Time (16) |
|01nullmm |                                                 |                 |
+---------+-------------------------------------------------+--------+--------+


     A             A + 1  ==>  A + N
+--------+----------------------------------------+
| Number |             First Ack                  |
|Blocks-1|           Block Length                 |
| (opt)  |(8, 16, 32 or 48 bits, determined by mm)|
+--------+----------------------------------------+

  A + N + 1                A + N + 2  ==>  T(aka A + 2N + 1)
+------------+-------------------------------------------------+
| Gap to next|              Ack Block Length                   |
| Block (8)  |   (8, 16, 32, or 48 bits, determined by mm)     |
| (Repeats)  |       (repeats Number Ranges times)             |
+------------+-------------------------------------------------+
     T        T+1             T+2                 (Repeated Num Timestamps)
+----------+--------+---------------------+ ...  --------+------------------+
|   Num    | Delta  |     Time Since      |     | Delta  |       Time       |
|Timestamps|Largest |    Largest Acked    |     |Largest |  Since Previous  |
|   (8)    | Acked  |      (32 bits)      |     | Acked  |Timestamp(16 bits)|
+----------+--------+---------------------+     +--------+------------------+
*/

type FirstTimestamp struct {
	DeltaLargestAcked     byte
	TimeSinceLargestAcked uint32
}

type NextTimestamp struct {
	DeltaLargestAcked     byte
	TimeSinceLargestAcked uint16
}
type AckFrame struct {
	*FramePacket
	Type                  FrameType
	Settings              byte
	LargestAcked          uint64
	LargestAckedDeltaTime uint16
	NumberBlocks_1        byte
	FirstAckBlockLength   uint64

	GapToNextBlock []byte
	AckBlockLength []uint64 // repeats NumberBlocks_1 times ???

	NumTimestamp byte
	Timestamp_1  FirstTimestamp // Repeat Num Timestamps
	Timestamps   []NextTimestamp
}

func NewAckFrame(largestAcked uint64, largestAckedDeltaTime uint16, blockLengthLen byte, blockLengths []uint64, firstTimestamp FirstTimestamp, nextTimestamps []NextTimestamp) *AckFrame {
	var settings byte
	// 'n' bit
	if len(blockLengths) > 0 {
		settings |= 0x20
	}

	// 'll' bits
	switch {
	case largestAcked <= 0xff:
		settings |= 0x00
	case largestAcked <= 0xffff:
		settings |= 0x04
	case largestAcked <= 0xffffff:
		settings |= 0x08
	case largestAcked <= 0xffffffff:
		settings |= 0x0c
	}

	// 'mm' bits
	switch blockLengthLen {
	case 1:
		settings |= 0x00
	case 2:
		settings |= 0x04
	case 4:
		settings |= 0x08
	case 6:
		settings |= 0x0c
	}

	numBlocks := 0
	if blockLengths != nil && len(blockLengths) > 0 {
		numBlocks = len(blockLengths)
	}

	ackFrame := &AckFrame{
		Type:                  AckFrameType,
		Settings:              settings,
		LargestAcked:          largestAcked,
		LargestAckedDeltaTime: largestAckedDeltaTime,
		NumberBlocks_1:        byte(numBlocks - 1), // byte(-1) = 255 means no data
		GapToNextBlock:        make([]byte, len(blockLengths)-1),
		AckBlockLength:        blockLengths,
		NumTimestamp:          byte(len(nextTimestamps) + 1),
		Timestamp_1:           firstTimestamp,
		Timestamps:            nextTimestamps,
	}
	return ackFrame
}

func ParseAckFrame(fp *FramePacket, data []byte) (Frame, int) {
	frame := &AckFrame{
		FramePacket: fp,
		Type:        AckFrameType,
		Settings:    data[0] & 0x3f,
	}

	myUint64 := func(idx, frameLen int) (buff uint64) {
		for i := 0; i < frameLen; i++ {
			buff |= uint64(data[idx+i]) << byte(8*(frameLen-i-1))
		}
		return buff
	}

	length := 1
	ll := int((frame.Settings & 0x0c) >> 2)
	lOLen := 1
	if ll != 0 {
		lOLen = ll * 2
	}

	frame.LargestAcked = myUint64(length, lOLen)
	length += lOLen
	frame.LargestAckedDeltaTime = binary.BigEndian.Uint16(data[length:])
	length += 2

	// has ack blocks
	if frame.Settings&0x20 == 0x20 {
		frame.NumberBlocks_1 = data[length]
		length++

		mm := int(frame.Settings & 0x03)
		mmLen := 1
		if mm != 0 {
			mmLen = mm * 2
		}

		frame.FirstAckBlockLength = myUint64(length, mmLen)
		length += mmLen
		for i := 0; i < int(frame.NumberBlocks_1); i++ {
			frame.GapToNextBlock[i] = data[length]
			frame.AckBlockLength[i] = myUint64(length+1, mmLen)
			length += mmLen + 1
		}
	}

	frame.NumTimestamp = data[length]
	length++
	frame.Timestamp_1.DeltaLargestAcked = data[length]
	frame.Timestamp_1.TimeSinceLargestAcked = binary.BigEndian.Uint32(data[length+1:])
	length += 5
	for i := 0; i < int(frame.NumTimestamp)-1; i++ {
		frame.Timestamps[i].DeltaLargestAcked = data[length]
		frame.Timestamps[i].TimeSinceLargestAcked = binary.BigEndian.Uint16(data[length+1:])
		length += 3
	}

	return frame, length
}

func (frame *AckFrame) GetWire() (wire []byte, err error) {
	myPutUint64 := func(wire []byte, dat uint64, size int) int {
		for i := 0; i < size; i++ {
			wire[i] = byte(dat >> byte(8*(size-i-1)))
		}
		return size
	}

	ll := int((frame.Settings & 0x0c) >> 2)
	lOLen := 1
	if ll != 0 {
		lOLen = ll * 2
	}

	blockRangeLen := 0
	mmLen := 0
	putAckBlock := func(wire []byte) (idx int) {
		return idx
	}
	if frame.Settings&0x20 == 0x20 {
		mm := int(frame.Settings & 0x03)
		mmLen = 1
		if mm != 0 {
			mmLen = mm * 2
		}
		blockRangeLen = (mmLen + 1) * int(frame.NumberBlocks_1+1)
		//override
		putAckBlock = func(wire []byte) (idx int) {
			wire[idx] = frame.NumberBlocks_1
			idx += 1 + myPutUint64(wire[idx+1:], frame.FirstAckBlockLength, mmLen)
			for i := 0; i < int(frame.NumberBlocks_1); i++ {
				wire[idx] = frame.GapToNextBlock[i]
				idx += 1 + myPutUint64(wire[idx+1:], frame.AckBlockLength[i], mmLen)
			}
			return idx
		}
	}

	timestampLen := 1
	putTimestamps := func(wire []byte) (idx int) {
		return 1
	}
	if frame.NumTimestamp > 0 {
		timestampLen += 5
		if frame.NumTimestamp > 1 {
			timestampLen += 3 * int(frame.NumTimestamp-1)
		}
		putTimestamps = func(wire []byte) (idx int) {
			wire[idx] = frame.NumTimestamp
			wire[idx+1] = frame.Timestamp_1.DeltaLargestAcked
			binary.BigEndian.PutUint32(wire[idx+2:], frame.Timestamp_1.TimeSinceLargestAcked)
			idx += 6
			for i := 0; i < int(frame.NumTimestamp); i++ {
				wire[idx] = frame.Timestamps[i].DeltaLargestAcked
				binary.BigEndian.PutUint16(wire[idx+1:], frame.Timestamps[i].TimeSinceLargestAcked)
				idx += 3
			}
			return idx
		}
	}

	wire = make([]byte, 1+lOLen+2+blockRangeLen+timestampLen)
	wire[0] = byte(frame.Type) | frame.Settings
	length := 1
	length += myPutUint64(wire[length:], frame.LargestAcked, lOLen)
	binary.BigEndian.PutUint16(wire[length:], frame.LargestAckedDeltaTime)
	length += 2
	length += putAckBlock(wire[length:])
	length += putTimestamps(wire[length:])
	return
}

func (frame *AckFrame) String() (str string) {
	str = fmt.Sprintf("ACK\n\t\t")
	return str
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

func ParseStopWaitingFrame(fp *FramePacket, data []byte) (Frame, int) {
	frame := &StopWaitingFrame{
		FramePacket: fp,
		Type:        StopWaitingFrameType,
		SentEntropy: data[1],
	}

	length := 0
	// the same length as the packet header's sequence number
	switch frame.PublicFlags & PACKET_NUMBER_LENGTH_MASK {
	case PACKET_NUMBER_LENGTH_6:
		length = 6
	case PACKET_NUMBER_LENGTH_4:
		length = 4
	case PACKET_NUMBER_LENGTH_2:
		length = 2
	case PACKET_NUMBER_LENGTH_1:
		length = 1
	}

	for i := 0; i < length; i++ {
		frame.LeastUnackedDelta |= uint64(data[2+i]) << byte(8*(length-i-1))
	}

	return frame, length + 2
}

func (frame *StopWaitingFrame) GetWire() (wire []byte, err error) {
	// shold here be functionized?
	length := 1
	switch frame.PublicFlags & PACKET_NUMBER_LENGTH_MASK {
	case PACKET_NUMBER_LENGTH_6:
		length = 6
	case PACKET_NUMBER_LENGTH_4:
		length = 4
	case PACKET_NUMBER_LENGTH_2:
		length = 2
	case PACKET_NUMBER_LENGTH_1:
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
	str = fmt.Sprintf("STOP WAITING\n\t\tSent Entropy : %d, Least unacked delta : %d",
		frame.SentEntropy, frame.LeastUnackedDelta)
	return str
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

func ParseWindowUpdateFrame(fp *FramePacket, data []byte) (Frame, int) {
	frame := &WindowUpdateFrame{
		FramePacket: fp,
		Type:        WindowUpdateFrameType,
	}
	frame.StreamID = binary.BigEndian.Uint32(data[1:])
	frame.Offset = binary.BigEndian.Uint64(data[5:])
	return frame, 13
}

func (frame *WindowUpdateFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 13)
	wire[0] = byte(frame.Type)
	binary.BigEndian.PutUint32(wire[1:], frame.StreamID)
	binary.BigEndian.PutUint64(wire[5:], frame.Offset)

	return
}

func (frame *WindowUpdateFrame) String() (str string) {
	str = fmt.Sprintf("WINDOW UPDATE\n\t\tStreamID : %d, Offset : %d",
		frame.StreamID, frame.Offset)
	return str
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

func ParseBlockedFrame(fp *FramePacket, data []byte) (Frame, int) {
	frame := &BlockedFrame{
		FramePacket: fp,
		Type:        BlockedFrameType,
	}
	frame.StreamID = binary.BigEndian.Uint32(data[1:])
	return frame, 5
}

func (frame *BlockedFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 5)
	wire[0] = byte(frame.Type)
	binary.BigEndian.PutUint32(wire[1:], frame.StreamID)

	return
}

func (frame *BlockedFrame) String() (str string) {
	str = fmt.Sprintf("BLOCKED\n\t\tStreamID %d", frame.StreamID)
	return str
}

// CongestionFeedback
func ParseCongestionFeedbackFrame(fp *FramePacket, data []uint8) (Frame, int) {
	return nil, 0
}

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

func ParsePaddingFrame(fp *FramePacket, data []byte) (Frame, int) {
	frame := &PaddingFrame{
		FramePacket: fp,
		Type:        PaddingFrameType,
	}
	return frame, len(data)
}

func (frame *PaddingFrame) GetWire() (wire []byte, err error) {
	// Frame Type is 0x00, no need to substitute
	wire = make([]byte, frame.RestSize)
	return
}
func (frame *PaddingFrame) String() (str string) {
	str = "PADDING\n\t\t"
	return str
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
	ErrorCode QUIC_OFFICIAL_ERROR
}

func NewRstStreamFrame(streamID uint32, offset uint64, errorCode QUIC_OFFICIAL_ERROR) *RstStreamFrame {
	rstStreamFrame := &RstStreamFrame{
		Type:      RstStreamFrameType,
		StreamID:  streamID,
		Offset:    offset,
		ErrorCode: errorCode,
	}
	return rstStreamFrame
}

func ParseRstStreamFrame(fp *FramePacket, data []byte) (Frame, int) {
	frame := &RstStreamFrame{
		FramePacket: fp,
		Type:        RstStreamFrameType,
	}
	frame.StreamID = binary.BigEndian.Uint32(data[1:])
	frame.Offset = binary.BigEndian.Uint64(data[5:])
	frame.ErrorCode = QUIC_OFFICIAL_ERROR(binary.BigEndian.Uint32(data[13:]))
	return frame, 17
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
	str = fmt.Sprintf("RST STREAM\n\t\tStreamID : %d, Offset : %d, Error code : %d",
		frame.StreamID, frame.Offset, frame.ErrorCode) // TODO: Error Code should be string
	return str
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

func ParsePingFrame(fp *FramePacket, data []byte) (Frame, int) {
	frame := &PingFrame{
		FramePacket: fp,
		Type:        PingFrameType,
	}
	return frame, 1
}
func (frame *PingFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 1)
	wire[0] = byte(frame.Type)
	return
}

func (frame *PingFrame) String() (str string) {
	str = fmt.Sprintf("PING\n\t\t")
	return str
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
	ErrorCode          QUIC_OFFICIAL_ERROR
	ReasonPhraseLength uint16
	ReasonPhrase       string
}

func NewConnectionCloseFrame(errorCode QUIC_OFFICIAL_ERROR, reasonPhrase string) *ConnectionCloseFrame {

	connectionCloseFrame := &ConnectionCloseFrame{
		Type:               ConnectionCloseFrameType,
		ErrorCode:          errorCode,
		ReasonPhraseLength: uint16(len(reasonPhrase)), // TODO: cut if the length is over uint16
		ReasonPhrase:       reasonPhrase,
	}
	return connectionCloseFrame
}

func ParseConnectionCloseFrame(fp *FramePacket, data []byte) (Frame, int) {
	frame := &ConnectionCloseFrame{
		FramePacket: fp,
		Type:        ConnectionCloseFrameType,
	}
	frame.ErrorCode = QUIC_OFFICIAL_ERROR(binary.BigEndian.Uint32(data[1:]))
	frame.ReasonPhraseLength = binary.BigEndian.Uint16(data[5:])
	frame.ReasonPhrase = string(data[7 : 7+frame.ReasonPhraseLength])
	return frame, 7 + int(frame.ReasonPhraseLength)
}

func (frame *ConnectionCloseFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 7+frame.ReasonPhraseLength)
	wire[0] = byte(frame.Type)
	binary.BigEndian.PutUint32(wire[1:], uint32(frame.ErrorCode))
	binary.BigEndian.PutUint16(wire[5:], frame.ReasonPhraseLength)
	copy(wire[7:], []byte(frame.ReasonPhrase))
	return
}

func (frame *ConnectionCloseFrame) String() (str string) {
	str = fmt.Sprintf("CONNECTION CLOSE\n\t\tError code : %d, Reason length : %d\nReason : %s",
		frame.ErrorCode, frame.ReasonPhraseLength, frame.ReasonPhrase)
	return str
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
	ErrorCode          QUIC_OFFICIAL_ERROR
	LastGoodStreamID   uint32
	ReasonPhraseLength uint16
	ReasonPhrase       string
}

func NewGoAwayFrame(errorCode QUIC_OFFICIAL_ERROR, lastGoodStreamID uint32, reasonPhrase string) *GoAwayFrame {
	goAwayFrame := &GoAwayFrame{
		Type:               GoAwayFrameType,
		ErrorCode:          errorCode,
		LastGoodStreamID:   lastGoodStreamID,
		ReasonPhraseLength: uint16(len(reasonPhrase)),
		ReasonPhrase:       reasonPhrase,
	}
	return goAwayFrame
}

func ParseGoAwayFrame(fp *FramePacket, data []byte) (Frame, int) {
	frame := &GoAwayFrame{
		FramePacket: fp,
		Type:        GoAwayFrameType,
	}
	frame.ErrorCode = QUIC_OFFICIAL_ERROR(binary.BigEndian.Uint32(data[1:]))
	frame.LastGoodStreamID = binary.BigEndian.Uint32(data[5:])
	frame.ReasonPhraseLength = binary.BigEndian.Uint16(data[9:])
	frame.ReasonPhrase = string(data[11 : 11+frame.ReasonPhraseLength])
	return frame, 11 + int(frame.ReasonPhraseLength)
}

func (frame *GoAwayFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 11+frame.ReasonPhraseLength)
	wire[0] = byte(frame.Type)
	binary.BigEndian.PutUint32(wire[1:], uint32(frame.ErrorCode))
	binary.BigEndian.PutUint32(wire[5:], frame.LastGoodStreamID)
	binary.BigEndian.PutUint16(wire[9:], frame.ReasonPhraseLength)
	copy(wire[11:], []byte(frame.ReasonPhrase))
	return
}

func (frame *GoAwayFrame) String() (str string) {
	str = fmt.Sprintf("GOAWAY\n\t\tError code : %d, LastGoodStreamID : %d, Reason length : %d\nReason : %s",
		frame.ErrorCode, frame.LastGoodStreamID, frame.ReasonPhraseLength, frame.ReasonPhrase)
	return str
}
