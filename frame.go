package quic

import (
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
	switch {
	case frameType&StreamFrameType == StreamFrameType:
		return "STREAM"
	case frameType&AckFrameType == AckFrameType:
		return "ACK"
	case frameType&CongestionFeedbackFrameType == CongestionFeedbackFrameType:
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
	Parse(data []byte) error
	GetWire() ([]byte, error)
	String() string
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

type StreamFrame struct {
	*FramePacket
	Type       FrameType
	StreamID   uint32
	Offset     uint64
	DataLength uint16
}

func NewStreamFrame(packet *FramePacket, fin bool, streamID uint32, offset uint64, dataLength uint16) *StreamFrame {
	var frameType FrameType = StreamFrameType
	if fin {
		frameType |= 0x40
	}
	if dataLength == 0 { // should other argument be used?
		frameType |= 0x20
	}

	// CHECK: are these bit length fixed?
	// 'ooo' bits
	switch {
	case offset == 0:
		frameType |= 0x00
	case offset <= 0xffff:
		frameType |= 0x04
	case offset <= 0xffffff:
		frameType |= 0x08
	case offset <= 0xffffffff:
		frameType |= 0x0c
	case offset <= 0xffffffffff:
		frameType |= 0x10
	case offset <= 0xffffffffffff:
		frameType |= 0x14
	case offset <= 0xffffffffffffff:
		frameType |= 0x18
	case offset <= 0xffffffffffffffff:
		frameType |= 0x1c
	}

	// 'ss' bits
	switch {
	case streamID <= 0xff:
		frameType |= 0x00
	case streamID <= 0xffff:
		frameType |= 0x01
	case streamID <= 0xffffff:
		frameType |= 0x02
	case streamID <= 0xffffffff:
		frameType |= 0x03
	}

	streamFrame := &StreamFrame{
		FramePacket: packet,
		Type:        frameType,
		StreamID:    streamID,
		Offset:      offset,
		DataLength:  dataLength,
	}
	return streamFrame
}

func (frame *StreamFrame) Parse(data []byte) (err error) {
	frame.Type = FrameType(data[0])
	if frame.Type&0x40 == 0x40 {
		//TODO: fin
	}

	index := 1
	switch frame.Type & 0x30 {
	case 0x00:
		frame.StreamID = uint32(data[1])
		index += 1
	case 0x01:
		frame.StreamID = uint32(data[1]<<8 | data[2])
		index += 2
	case 0x02:
		frame.StreamID = uint32(data[1]<<16 | data[2]<<8 | data[3])
		index += 3
	case 0x03:
		frame.StreamID = uint32(data[1]<<24 | data[2]<<16 | data[3]<<8 | data[4])
		index += 4
	}

	switch frame.Type & 0x1c {
	case 0x00:
		frame.Offset = uint64(data[index])
		index += 1
	case 0x04:
		frame.Offset = uint64(data[index]<<8 | data[index+1])
		index += 2
	case 0x08:
		frame.Offset = uint64(data[index]<<16 | data[index+1]<<8 | data[index+2])
		index += 3
	case 0x0c:
		for i := 0; i < 4; i++ {
			frame.Offset |= uint64(data[index+i] << byte(8*(3-i)))
		}
		index += 4
	case 0x10:
		for i := 0; i < 5; i++ {
			frame.Offset |= uint64(data[index+i] << byte(8*(4-i)))
		}
		index += 5
	case 0x14:
		for i := 0; i < 6; i++ {
			frame.Offset |= uint64(data[index+i] << byte(8*(5-i)))
		}
		index += 6
	case 0x18:
		for i := 0; i < 7; i++ {
			frame.Offset |= uint64(data[index+i] << byte(8*(6-i)))
		}
		index += 7
	case 0x1c:
		for i := 0; i < 8; i++ {
			frame.Offset |= uint64(data[index+i] << byte(8*(7-i)))
		}
		index += 8
	}

	frame.DataLength = 0 // as is not contained. right?
	if frame.Type&0x20 == 0x20 {
		frame.DataLength = uint16(data[index]<<8 | data[index])
	}

	return
}

func (frame *StreamFrame) GetWire() (wire []byte, err error) {
	// data length's length
	DLEN := int((frame.Type & 0x20 >> 5) * 2)

	// streamID length
	SLEN := int((frame.Type & 0x03) + 1)

	// offset length
	OLEN := int((frame.Type & 0x1c >> 2))
	if OLEN > 0 {
		OLEN += 1
	}

	wire = make([]byte, 1+DLEN+SLEN+OLEN)
	wire[0] = byte(frame.Type)
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
		wire[index] = byte(frame.DataLength >> 8)
		wire[index+1] = byte(frame.DataLength)
	}
	return
}

func (frame *StreamFrame) String() (str string) {
	str = fmt.Sprintf("STREAM\nStreamID : %d, Offset : %d, DataLength : %d",
		frame.StreamID, frame.Offset, frame.DataLength)
	return str
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
	Type                             FrameType
	RecievedEntropy                  byte
	LargestObserved                  uint64
	LargestObservedDeltaTime         float64 // this must be ufloat64?
	NumTimestamp                     byte
	DeltaLargestObserved             byte
	TimeSinceLargestObserved         uint32
	TimeSincePreviousTimestamp       uint16
	NumRages                         byte
	MissingPacketSequenceNumberDelta []byte //suspicious
	RangeLength                      byte
	NumberRevived                    byte
	RevivedPacket                    uint64
}

func NewAckFrame(packet *FramePacket, hasNACK, isTruncate bool, largestObserved, missingDelta uint64) *AckFrame {
	frameType := AckFrameType
	// 'n' bit
	if hasNACK {
		frameType |= 0x20
	}
	// 't' bit
	if isTruncate {
		frameType |= 0x10
	}

	// 'll' bits
	switch {
	case largestObserved <= 0xff:
		frameType |= 0x00
	case largestObserved <= 0xffff:
		frameType |= 0x04
	case largestObserved <= 0xffffff:
		frameType |= 0x08
	case largestObserved <= 0xffffffff:
		frameType |= 0x0c
	}

	// 'mm' bits
	switch {
	case missingDelta <= 0xff:
		frameType |= 0x00
	case missingDelta <= 0xffff:
		frameType |= 0x04
	case missingDelta <= 0xffffff:
		frameType |= 0x08
	case missingDelta <= 0xffffffff:
		frameType |= 0x0c
	}

	ackFrame := &AckFrame{
		FramePacket: packet,
	}
	return ackFrame
}
func (frame *AckFrame) String() (str string) {
	str = fmt.Sprintf("ACK\n")
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

func NewStopWaitingFrame(packet *FramePacket, sentEntropy byte, leastUnackedDelta uint64) *StopWaitingFrame {
	stopWaitingFrame := &StopWaitingFrame{
		FramePacket:       packet,
		Type:              StopWaitingFrameType,
		SentEntropy:       sentEntropy,
		LeastUnackedDelta: leastUnackedDelta,
	}
	return stopWaitingFrame
}

func (frame *StopWaitingFrame) Parse(data []byte) (err error) {
	frame.Type = FrameType(data[0])
	frame.SentEntropy = data[1]

	// the same length as the packet header's sequence number
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
	for i := 0; i < length; i++ {
		frame.LeastUnackedDelta |= uint64(data[2+i] << byte(8*(length-i-1)))
	}

	return
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
	str = fmt.Sprintf("STOP WAITING\nSent Entropy : %d, Least unacked delta : %d",
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

func NewWindowUpdateFrame(packet *FramePacket, streamID uint32, offset uint64) *WindowUpdateFrame {
	windowUpdateFrame := &WindowUpdateFrame{
		FramePacket: packet,
		Type:        WindowUpdateFrameType,
		StreamID:    streamID,
		Offset:      offset,
	}
	return windowUpdateFrame
}

func (frame *WindowUpdateFrame) Parse(data []byte) (err error) {
	frame.Type = FrameType(data[0])
	frame.StreamID = uint32(data[1]<<24 | data[2]<<16 | data[3]<<8 | data[4])
	for i := 0; i < 8; i++ {
		frame.Offset |= uint64(data[5+i] << byte(8*(7-i)))
	}
	return
}

func (frame *WindowUpdateFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 13)
	wire[0] = byte(frame.Type)
	for i := 0; i < 4; i++ {
		wire[1+i] = byte(frame.StreamID >> byte(8*(3-i)))
	}
	for i := 0; i < 8; i++ {
		wire[5+i] = byte(frame.Offset >> byte(8*(7-i)))
	}

	return
}

func (frame *WindowUpdateFrame) String() (str string) {
	str = fmt.Sprintf("WINDOW UPDATE\nStreamID : %d, Offset : %d",
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

func NewBlockedFrame(packet *FramePacket, streamID uint32) *BlockedFrame {
	blockedFrame := &BlockedFrame{
		FramePacket: packet,
		Type:        BlockedFrameType,
		StreamID:    streamID,
	}
	return blockedFrame
}

func (frame *BlockedFrame) Parse(data []byte) (err error) {
	frame.Type = FrameType(data[0])
	frame.StreamID = uint32(data[1]<<24 | data[2]<<16 | data[3]<<8 | data[4])
	return
}

func (frame *BlockedFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 5)
	wire[0] = byte(frame.Type)
	for i := 0; i < 4; i++ {
		wire[1+i] = byte(frame.StreamID >> byte(8*(3-i)))
	}

	return
}

func (frame *BlockedFrame) String() (str string) {
	str = fmt.Sprintf("BLOCKED\nStreamID %d", frame.StreamID)
	return str
}

// CongestionFeedback
type PaddingFrame struct {
	*FramePacket
	Type FrameType
}

func NewPadding(packet *FramePacket) *PaddingFrame {
	paddingFrame := &PaddingFrame{
		FramePacket: packet,
		Type:        PaddingFrameType,
	}
	return paddingFrame
}

func (frame *PaddingFrame) Parse(data []byte) (err error) {
	// TODO: do something?
	return
}

func (frame *PaddingFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 1)
	wire[0] = byte(frame.Type)
	return
}
func (frame *PaddingFrame) String() (str string) {
	str = "PADDING\n"
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
	ErrorCode QuicErrorCode
}

func NewRstStreamFrame(packet *FramePacket, streamID uint32, offset uint64, errorCode QuicErrorCode) *RstStreamFrame {
	rstStreamFrame := &RstStreamFrame{
		FramePacket: packet,
		Type:        RstStreamFrameType,
		StreamID:    streamID,
		Offset:      offset,
		ErrorCode:   errorCode,
	}
	return rstStreamFrame
}

func (frame *RstStreamFrame) Parse(data []byte) (err error) {
	frame.Type = FrameType(data[0])
	frame.StreamID = uint32(data[1]<<24 | data[2]<<16 | data[3]<<8 | data[4])
	for i := 0; i < 8; i++ {
		frame.Offset |= uint64(data[5+i] << byte(8*(7-i)))
	}
	frame.ErrorCode = QuicErrorCode(data[13]<<24 | data[14]<<16 | data[15]<<8 | data[16])
	return
}

func (frame *RstStreamFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 17)
	wire[0] = byte(frame.Type)
	for i := 0; i < 4; i++ {
		wire[1+i] = byte(frame.StreamID >> byte(8*(3-i)))
	}
	for i := 0; i < 8; i++ {
		wire[5+i] = byte(frame.Offset >> byte(8*(7-i)))
	}
	for i := 0; i < 4; i++ {
		wire[13+i] = byte(frame.ErrorCode >> byte(8*(3-i)))
	}
	return
}

func (frame *RstStreamFrame) String() (str string) {
	str = fmt.Sprintf("RST STREAM\nStreamID : %d, Offset : %d, Error code : %d",
		frame.StreamID, frame.Offset, frame.ErrorCode) // TODO: Error Code should be string
	return str
}

type PingFrame struct {
	*FramePacket
	Type FrameType
}

func NewPingFrame(packet *FramePacket) *PingFrame {
	pingFrame := &PingFrame{
		FramePacket: packet,
		Type:        PingFrameType,
	}
	return pingFrame
}

func (frame *PingFrame) Parse(data []byte) (err error) {
	frame.Type = FrameType(data[0])
	return
}
func (frame *PingFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 1)
	wire[0] = byte(frame.Type)
	return
}

func (frame *PingFrame) String() (str string) {
	str = fmt.Sprintf("PING\n")
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
	ErrorCode          QuicErrorCode
	ReasonPhraseLength uint16
	ReasonPhrase       string
}

func NewConnectionCloseFrame(packet *FramePacket, errorCode QuicErrorCode, reasonPhrase string) *ConnectionCloseFrame {

	connectionCloseFrame := &ConnectionCloseFrame{
		FramePacket:        packet,
		Type:               ConnectionCloseFrameType,
		ErrorCode:          errorCode,
		ReasonPhraseLength: uint16(len(reasonPhrase)), // TODO: cut if the length is over uint16
		ReasonPhrase:       reasonPhrase,
	}
	return connectionCloseFrame
}

func (frame *ConnectionCloseFrame) Parse(data []byte) (err error) {
	frame.Type = FrameType(data[0])
	frame.ErrorCode = QuicErrorCode(data[1]<<24 | data[2]<<16 | data[3]<<8 | data[4])
	frame.ReasonPhraseLength = uint16(data[5]<<8 | data[6])
	frame.ReasonPhrase = string(data[7 : 7+frame.ReasonPhraseLength])
	return
}

func (frame *ConnectionCloseFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 7+frame.ReasonPhraseLength)
	wire[0] = byte(frame.Type)
	for i := 0; i < 4; i++ {
		wire[1+i] = byte(frame.ErrorCode >> byte(8*(3-i)))
	}
	wire[5] = byte(frame.ReasonPhraseLength >> 8)
	wire[6] = byte(frame.ReasonPhraseLength)

	byteString := []byte(frame.ReasonPhrase)
	for i, v := range byteString {
		wire[7+i] = v
	}
	return
}

func (frame *ConnectionCloseFrame) String() (str string) {
	str = fmt.Sprintf("CONNECTION CLOSE\n Error code : %d, Reason length : %d\nReason : %s",
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
	ErrorCode          QuicErrorCode
	LastGoodStreamID   uint32
	ReasonPhraseLength uint16
	ReasonPhrase       string
}

func NewGoAwayFrame(packet *FramePacket, errorCode QuicErrorCode, lastGoodStreamID uint32, reasonPhrase string) *GoAwayFrame {
	goAwayFrame := &GoAwayFrame{
		FramePacket:        packet,
		Type:               GoAwayFrameType,
		ErrorCode:          errorCode,
		LastGoodStreamID:   lastGoodStreamID,
		ReasonPhraseLength: uint16(len(reasonPhrase)),
		ReasonPhrase:       reasonPhrase,
	}
	return goAwayFrame
}

func (frame *GoAwayFrame) Parse(data []byte) (err error) {
	frame.Type = FrameType(data[0])
	frame.ErrorCode = QuicErrorCode(data[1]<<24 | data[2]<<16 | data[3]<<8 | data[4])
	frame.LastGoodStreamID = uint32(data[5]<<24 | data[6]<<16 | data[7]<<8 | data[8])
	frame.ReasonPhraseLength = uint16(data[9]<<8 | data[10])
	frame.ReasonPhrase = string(data[11 : 11+frame.ReasonPhraseLength])
	return
}

func (frame *GoAwayFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 11+frame.ReasonPhraseLength)
	wire[0] = byte(frame.Type)
	for i := 0; i < 4; i++ {
		wire[1+i] = byte(frame.ErrorCode >> byte(8*(3-i)))
	}
	for i := 0; i < 4; i++ {
		wire[5+i] = byte(frame.LastGoodStreamID >> byte(8*(3-i)))
	}

	wire[9] = byte(frame.ReasonPhraseLength >> 8)
	wire[10] = byte(frame.ReasonPhraseLength)

	byteString := []byte(frame.ReasonPhrase)
	for i, v := range byteString {
		wire[11+i] = v
	}

	return
}

func (frame *GoAwayFrame) String() (str string) {
	str = fmt.Sprintf("GOAWAY\n Error code : %d, LastGoodStreamID : %d, Reason length : %d\nReason : %s",
		frame.ErrorCode, frame.LastGoodStreamID, frame.ReasonPhraseLength, frame.ReasonPhrase)
	return str
}
