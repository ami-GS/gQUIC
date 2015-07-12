package quic

const QUIC_VERSION = uint32('Q'<<24 | '0'<<16 | '1'<<8 | '5') // temporally

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

type PublicFlagType byte

const (
	CONTAIN_QUIC_VERSION        PublicFlagType = 0x01
	PUBLIC_RESET                               = 0x02
	CONNECTION_ID_LENGTH_MASK                  = 0x0c
	CONNECTION_ID_LENGTH_8                     = 0x0c
	CONNECTION_ID_LENGTH_4                     = 0x08
	CONNECTION_ID_LENGTH_1                     = 0x04
	OMIT_CONNECTION_ID                         = 0x00
	SEQUENCE_NUMBER_LENGTH_MASK                = 0x30
	SEQUENCE_NUMBER_LENGTH_6                   = 0x30
	SEQUENCE_NUMBER_LENGTH_4                   = 0x20
	SEQUENCE_NUMBER_LENGTH_2                   = 0x10
	SEQUENCE_NUMBER_LENGTH_1                   = 0x00
	RESERVED                                   = 0xc0
)

type PrivateFlagType byte

const (
	FLAG_ENTROPY   PrivateFlagType = 0x01
	FLAG_FEC_GROUP                 = 0x02
	FLAG_FEC                       = 0x04
)

type QuicErrorCode uint32

const (
	NO_ERROR QuicErrorCode = iota
	// TODO: write down Error code
	// the details are stil in progress?

)

// Frame Header
/*
+--------+--------+--------+--------+--------+---    ---+
| Public |    Connection ID (0, 8, 32, or 64)    ...    | ->
|Flags(8)|      (variable length)                       |
+--------+--------+--------+--------+--------+---    ---+

    9       10       11        12
+--------+--------+--------+--------+
|      Quic Version (32)            | ->
|         (optional)                |
+--------+--------+--------+--------+

    13      14       15        16        17       18       19       20
+--------+--------+--------+--------+--------+--------+--------+--------+
|         Sequence Number (8, 16, 32, or 48)          |Private | FEC (8)|
|                         (variable length)           |Flags(8)|  (opt) |
+--------+--------+--------+--------+--------+--------+--------+--------+
*/

type FrameHeader struct {
	PublicFlags    PublicFlagType
	ConnectionID   uint64
	Version        uint32
	SequenceNumber uint64
	PrivateFlags   PrivateFlagType
	FEC            byte
}

func NewFrameHeader(connectionID uint64, version uint32, sequenceNumber uint64, privateFlags PrivateFlagType, fec byte) *FrameHeader {
	var publicFlags PublicFlagType = 0x00
	switch {
	case connectionID <= 0:
		publicFlags |= OMIT_CONNECTION_ID
	case connectionID <= 0xff:
		publicFlags |= CONNECTION_ID_LENGTH_1
	case connectionID <= 0xffffffff:
		publicFlags |= CONNECTION_ID_LENGTH_4
	case connectionID <= 0xffffffffffffffff:
		publicFlags |= CONNECTION_ID_LENGTH_8
	}

	switch {
	case sequenceNumber <= 0xff:
		publicFlags |= SEQUENCE_NUMBER_LENGTH_1
	case sequenceNumber <= 0xffff:
		publicFlags |= SEQUENCE_NUMBER_LENGTH_2
	case sequenceNumber <= 0xffffffff:
		publicFlags |= SEQUENCE_NUMBER_LENGTH_4
	case sequenceNumber <= 0xffffffffffff:
		publicFlags |= SEQUENCE_NUMBER_LENGTH_6
	}

	fh := &FrameHeader{
		PublicFlags:    publicFlags,
		ConnectionID:   connectionID,
		Version:        version,
		SequenceNumber: sequenceNumber,
		PrivateFlags:   privateFlags,
		FEC:            fec,
	}
	return fh
}

func (fh *FrameHeader) Parse(data []byte) (err error) {
	index := 0
	fh.PublicFlags = PublicFlagType(data[index])

	switch fh.PublicFlags & CONNECTION_ID_LENGTH_MASK {
	case CONNECTION_ID_LENGTH_8:
		fh.ConnectionID = uint64(data[1]<<56 | data[2]<<48 | data[3]<<40 | data[4]<<32 | data[5]<<24 | data[6]<<16 | data[7]<<8 | data[8])
		index = 9
	case CONNECTION_ID_LENGTH_4:
		fh.ConnectionID = uint64(data[1]<<24 | data[2]<<16 | data[3]<<8 | data[4])
		index = 5
	case CONNECTION_ID_LENGTH_1:
		fh.ConnectionID = uint64(data[1])
		index = 2
	case OMIT_CONNECTION_ID:
		fh.ConnectionID = 0 // omitted
		index = 1

	}

	if fh.PublicFlags&CONTAIN_QUIC_VERSION == CONTAIN_QUIC_VERSION {
		fh.Version = uint32(data[index]<<24 | data[index+1]<<16 | data[index+2]<<8 | data[index+3])
		index += 4
	}

	// TODO: parse sequence number
	switch fh.PublicFlags & SEQUENCE_NUMBER_LENGTH_MASK {
	case SEQUENCE_NUMBER_LENGTH_6:
		fh.SequenceNumber = uint64(data[index]<<40 | data[index+1]<<32 | data[index+2]<<24 | data[index+3]<<16 | data[index+4]<<8 | data[index+5])
		index += 6
	case SEQUENCE_NUMBER_LENGTH_4:
		fh.SequenceNumber = uint64(data[index]<<24 | data[index+1]<<16 | data[index+2]<<8 | data[index+3])
		index += 4
	case SEQUENCE_NUMBER_LENGTH_2:
		fh.SequenceNumber = uint64(data[index]<<8 | data[index+1])
		index += 2
	case SEQUENCE_NUMBER_LENGTH_1:
		fh.SequenceNumber = uint64(data[index])
		index += 1
	}

	fh.PrivateFlags = PrivateFlagType(data[index])
	if fh.PrivateFlags&FLAG_ENTROPY == FLAG_ENTROPY {
		// TODO: ?
	}
	if fh.PrivateFlags&FLAG_FEC_GROUP == FLAG_FEC_GROUP {
		fh.FEC = data[index]
	}
	if fh.PrivateFlags&FLAG_FEC == FLAG_FEC {
		//TODO: FEC packet
	}

	return
}

func (fh *FrameHeader) GetWire() (wire []byte, err error) {
	// confirm variable length
	connectionIDLen := 0
	switch fh.PublicFlags & CONNECTION_ID_LENGTH_MASK {
	case CONNECTION_ID_LENGTH_8:
		connectionIDLen = 8
	case CONNECTION_ID_LENGTH_4:
		connectionIDLen = 4
	case CONNECTION_ID_LENGTH_1:
		connectionIDLen = 1
	case OMIT_CONNECTION_ID:
		//pass
	}

	versionLen := 0
	if fh.PublicFlags&0x01 > 0 {
		versionLen = 4
	}

	sequenceNumberLen := 1
	switch fh.PublicFlags & SEQUENCE_NUMBER_LENGTH_MASK {
	case SEQUENCE_NUMBER_LENGTH_6:
		sequenceNumberLen = 6
	case SEQUENCE_NUMBER_LENGTH_4:
		sequenceNumberLen = 4
	case SEQUENCE_NUMBER_LENGTH_2:
		sequenceNumberLen = 2
	case SEQUENCE_NUMBER_LENGTH_1:
		//pass
	}

	// deal with FEC part
	fecLen := 0
	if fh.PrivateFlags&FLAG_ENTROPY == FLAG_ENTROPY {
		// TODO: ?
	}
	if fh.PrivateFlags&FLAG_FEC_GROUP == FLAG_FEC_GROUP {
		fecLen = 1
	}
	if fh.PrivateFlags&FLAG_FEC == FLAG_FEC {
		//TODO: FEC packet
	}

	// pack to wire
	wire = make([]byte, 1+connectionIDLen+versionLen+sequenceNumberLen+1+fecLen)
	wire[0] = byte(fh.PublicFlags)
	index := 1
	for i := 0; i < connectionIDLen; i++ {
		wire[index+i] = byte(fh.ConnectionID >> byte(8*(connectionIDLen-i-1)))
	}
	index += connectionIDLen

	for i := 0; i < versionLen; i++ {
		wire[index+i] = byte(fh.Version >> byte(8*(versionLen-i-1)))
	}
	index += versionLen

	for i := 0; i < sequenceNumberLen; i++ {
		wire[index+i] = byte(fh.SequenceNumber >> byte(8*(sequenceNumberLen-i-1)))
	}
	index += sequenceNumberLen

	wire[index] = byte(fh.PrivateFlags)

	if fecLen > 0 {
		wire[index+1] = fh.FEC
	}

	return
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
	*FrameHeader
	Type       FrameType
	StreamID   uint32
	Offset     uint64
	DataLength uint16
}

func NewStreamFrame(fin bool, streamID uint32, offset uint64, dataLength uint16) *StreamFrame {
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

	//fh := NewFrameHeader()
	fh := &FrameHeader{} //temporaly
	streamFrame := &StreamFrame{
		FrameHeader: fh,
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
	switch {
	case frame.Type&0x03 == 0x00:
		frame.StreamID = uint32(data[1])
		index += 1
	case frame.Type&0x03 == 0x01:
		frame.StreamID = uint32(data[1]<<8 | data[2])
		index += 2
	case frame.Type&0x03 == 0x02:
		frame.StreamID = uint32(data[1]<<16 | data[2]<<8 | data[3])
		index += 3
	case frame.Type&0x03 == 0x03:
		frame.StreamID = uint32(data[1]<<24 | data[2]<<16 | data[3]<<8 | data[4])
		index += 4
	}

	switch {
	case frame.Type&0x1c == 0x00:
		frame.Offset = uint64(data[index])
		index += 1
	case frame.Type&0x1c == 0x04:
		frame.Offset = uint64(data[index]<<8 | data[index+1])
		index += 2
	case frame.Type&0x1c == 0x08:
		frame.Offset = uint64(data[index]<<16 | data[index+1]<<8 | data[index+2])
		index += 3
	case frame.Type&0x1c == 0x0c:
		for i := 0; i < 4; i++ {
			frame.Offset |= uint64(data[index+i] << byte(8*(3-i)))
		}
		index += 4
	case frame.Type&0x1c == 0x10:
		for i := 0; i < 5; i++ {
			frame.Offset |= uint64(data[index+i] << byte(8*(4-i)))
		}
		index += 5
	case frame.Type&0x1c == 0x14:
		for i := 0; i < 6; i++ {
			frame.Offset |= uint64(data[index+i] << byte(8*(5-i)))
		}
		index += 6
	case frame.Type&0x1c == 0x18:
		for i := 0; i < 7; i++ {
			frame.Offset |= uint64(data[index+i] << byte(8*(6-i)))
		}
		index += 7
	case frame.Type&0x1c == 0x1c:
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
	*FrameHeader
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

func NewAckFrame(hasNACK, isTruncate bool, largestObserved, missingDelta uint64) *AckFrame {
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

	fh := &FrameHeader{} //temporally
	ackFrame := &AckFrame{
		FrameHeader: fh,
	}
	return
}

/*
      0        1        2        3         4        5        6      7
 +--------+--------+--------+--------+--------+--------+-------+-------+
 |Type (8)|Sent    |   Least unacked delta (8, 16, 32, or 48 bits)     |
 |        |Entropy |                       (variable length)           |
 +--------+--------+--------+--------+--------+--------+-------+-------+
*/

type StopWaitingFrame struct {
	*FrameHeader
	Type              FrameType
	SentEntropy       byte
	LeastUnackedDelta uint64
}

func NewStopWaitingFrame(sentEntropy byte, leastUnackedDelta uint64) *StopWaitingFrame {
	fh := &FrameHeader{} // temporaly
	stopWaitingFrame := &StopWaitingFrame{
		FrameHeader:       fh,
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
	switch {
	case frame.PublicFlags&0x30 == 0x30:
		length = 6
	case frame.PublicFlags&0x20 == 0x20:
		length = 4
	case frame.PublicFlags&0x10 == 0x10:
		length = 2
	}
	for i := 0; i < length; i++ {
		frame.LeastUnackedDelta |= uint64(data[2+i] << byte(8*(length-i-1)))
	}

	return
}

func (frame *StopWaitingFrame) GetWire() (wire []byte, err error) {
	// shold here be functionized?
	length := 1
	switch {
	case frame.PublicFlags&0x30 == 0x30:
		length = 6
	case frame.PublicFlags&0x20 == 0x20:
		length = 4
	case frame.PublicFlags&0x10 == 0x10:
		length = 2
	}

	wire = make([]byte, 2+length)
	wire[0] = byte(frame.Type)
	wire[1] = frame.SentEntropy

	for i := 0; i < length; i++ {
		wire[2+i] = byte(frame.LeastUnackedDelta >> byte(8*(length-i-1)))
	}

	return
}

/*
     0         1                 4        5                 12
 +--------+--------+-- ... --+-------+--------+-- ... --+-------+
 |Type(8) |    Stream ID (32 bits)   |  Byte offset (64 bits)   |
 +--------+--------+-- ... --+-------+--------+-- ... --+-------+
*/

type WindowUpdateFrame struct {
	*FrameHeader
	Type     FrameType
	StreamID uint32
	Offset   uint64
}

func NewWindowUpdateFrame(streamID uint32, offset uint64) *WindowUpdateFrame {
	fh := &FrameHeader{} //temporaly
	windowUpdateFrame := &WindowUpdateFrame{
		FrameHeader: fh,
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

/*
      0        1        2        3         4
 +--------+--------+--------+--------+--------+
 |Type(8) |          Stream ID (32 bits)      |
 +--------+--------+--------+--------+--------+
*/
type BlockedFrame struct {
	*FrameHeader
	Type     FrameType
	StreamID uint32
}

func NewBlockedFrame(streamID uint32) *BlockedFrame {
	fh := &FrameHeader{} //temporaly
	blockedFrame := &BlockedFrame{
		FrameHeader: fh,
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

// CongestionFeedback
type PaddingFrame struct {
	*FrameHeader
	Type FrameType
}

func NewPadding() *PaddingFrame {
	fh := &FrameHeader{} //temporally
	paddingFrame := &PaddingFrame{
		FrameHeader: fh,
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

/*
     0        1            4      5              12     8             16
+-------+--------+-- ... ----+--------+-- ... ------+-------+-- ... ------+
|Type(8)| StreamID (32 bits) | Byte offset (64 bits)| Error code (32 bits)|
+-------+--------+-- ... ----+--------+-- ... ------+-------+-- ... ------+
*/

type RstStreamFrame struct {
	*FrameHeader
	Type      FrameType
	StreamID  uint32
	Offset    uint64
	ErrorCode QuicErrorCode
}

func NewRstStreamFrame(streamID uint32, offset uint64, errorCode QuicErrorCode) *RstStreamFrame {
	fh := &FrameHeader{} //temporally
	rstStreamFrame := &RstStreamFrame{
		FrameHeader: fh,
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

type PingFrame struct {
	*FrameHeader
	Type FrameType
}

func NewPingFrame() *PingFrame {
	fh := &FrameHeader{} //temporally
	pingFrame := &PingFrame{
		FrameHeader: fh,
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

/*
        0        1             4        5        6       7
   +--------+--------+-- ... -----+--------+--------+--------+----- ...
   |Type(8) | Error code (32 bits)| Reason phrase   |  Reason phrase
   |        |                     | length (16 bits)|(variable length)
   +--------+--------+-- ... -----+--------+--------+--------+----- ...
*/

type ConnectionCloseFrame struct {
	*FrameHeader
	Type               FrameType
	ErrorCode          QuicErrorCode
	ReasonPhraseLength uint16
	ReasonPhrase       string
}

func NewConnectionCloseFrame(errorCode QuicErrorCode, reasonPhrase string) *ConnectionCloseFrame {
	fh := &FrameHeader{} //temporally
	connectionCloseFrame := &ConnectionCloseFrame{
		FrameHeader:        fh,
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
	*FrameHeader
	Type               FrameType
	ErrorCode          QuicErrorCode
	LastGoodStreamID   uint32
	ReasonPhraseLength uint16
	ReasonPhrase       string
}

func NewGoAwayFrame(errorCode QuicErrorCode, lastGoodStreamID uint32, reasonPhrase string) *GoAwayFrame {
	fh := &FrameHeader{} // temporally
	goAwayFrame := &GoAwayFrame{
		FrameHeader:        fh,
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
