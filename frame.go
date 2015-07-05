package quic

type FrameType uint8

const (
	PaddingFrameType FrameType = iota
	RstStreamFrameType
	ConnectionCloseFrameType
	GoawayFrameType
	WindowUpdateFrameType
	BlockedFrameType
	StopWaitingFrameType
	PingFrameType
	StreamFrameType             = 0x80
	AckFrameType                = 0x40
	CongestionFeedbackFrameType = 0x20
)

type PublicFlags uint8

const (
	QUIC_VERSION              PublicFlags = 0x01
	PUBLIC_RESET                          = 0x02
	CONTAIN_CONNECTION_ID_8               = 0x0c
	CONTAIN_CONNECTION_ID_4               = 0x08
	CONTAIN_CONNECTION_ID_1               = 0x04
	OMIT_CONNECTION_ID                    = 0x00
	CONTAIN_SEQUENCE_NUMBER_6             = 0x30
	CONTAIN_SEQUENCE_NUMBER_4             = 0x20
	CONTAIN_SEQUENCE_NUMBER_2             = 0x10
	CONTAIN_SEQUENCE_NUMBER_1             = 0x00
	RESERVED                              = 0xc0
)

type PrivateFlags uint8

const (
	FLAG_ENTROPY   PrivateFlags = 0x01
	FLAG_FEC_GROUP              = 0x02
	FLAG_FEC                    = 0x03
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
	PublicFlags    byte
	ConnectionID   uint64
	Version        uint32
	SequenceNumber uint64
	PrivateFlags   byte
	FEC            byte
}

func NewFrameHeader(publicFlags byte, connectionID uint64, version uint32, sequenceNumber uint64, privateFlags, fec byte) *FrameHeader {
	fh := &FrameHeader{
		publicFlags,
		connectionID,
		version,
		sequenceNumber,
		privateFlags,
		fec,
	}
	return fh
}

func (fh *FrameHeader) Parse(data []byte) (err error) {
	index := 0
	fh.PublicFlags = data[index]

	if fh.PublicFlags&0x0c == 0x0c {
		fh.ConnectionID = uint64(data[1]<<56 | data[2]<<48 | data[3]<<40 | data[4]<<32 | data[5]<<24 | data[6]<<16 | data[7]<<8 | data[8])
		index = 9
	} else if fh.PublicFlags&0x08 == 0x08 {
		fh.ConnectionID = uint64(data[1]<<24 | data[2]<<16 | data[3]<<8 | data[4])
		index = 5
	} else if fh.PublicFlags&0x04 == 0x04 {
		fh.ConnectionID = uint64(data[1])
		index = 2
	} else {
		fh.ConnectionID = 0 // omitted
		index = 1
	}

	if fh.PublicFlags&0x01 == 0x01 {
		fh.Version = uint32(data[index]<<24 | data[index+1]<<16 | data[index+2]<<8 | data[index+3])
		index += 4
	}

	// TODO: parse sequence number
	if fh.PublicFlags&0x30 == 0x30 {
		fh.SequenceNumber = uint64(data[index]<<40 | data[index+1]<<32 | data[index+2]<<24 | data[index+3]<<16 | data[index+4]<<8 | data[index+5])
		index += 6
	} else if fh.PublicFlags&0x20 == 0x20 {
		fh.SequenceNumber = uint64(data[index]<<24 | data[index+1]<<16 | data[index+2]<<8 | data[index+3])
		index += 4
	} else if fh.PublicFlags&0x10 == 0x10 {
		fh.SequenceNumber = uint64(data[index]<<8 | data[index+1])
		index += 2
	} else if fh.PublicFlags&0x00 == 0x00 {
		fh.SequenceNumber = uint64(data[index])
		index += 1
	}

	fh.PrivateFlags = data[index]

	// TODO: parse FEC
	return
}

func (fh *FrameHeader) GetWire() (wire []byte, err error) {
	// confirm variable length
	connectionIDLen := 0
	if fh.PublicFlags&0x0c == 0x0c {
		connectionIDLen = 8
	} else if fh.PublicFlags&0x08 == 0x08 {
		connectionIDLen = 4
	} else if fh.PublicFlags&0x04 == 0x04 {
		connectionIDLen = 1
	}

	versionLen := 0
	if fh.PublicFlags&0x01 > 0 {
		versionLen = 4
	}

	sequenceNumberLen := 1
	if fh.PublicFlags&0x30 == 0x30 {
		sequenceNumberLen = 6
	} else if fh.PublicFlags&0x20 == 0x20 {
		sequenceNumberLen = 4
	} else if fh.PublicFlags&0x10 == 0x10 {
		sequenceNumberLen = 2
	}

	// deal with FEC part
	fecLen := 1 // temporaly

	// pack to wire
	wire = make([]byte, 1+connectionIDLen+versionLen+sequenceNumberLen+1+fecLen)
	wire[0] = byte(fh.PublicFlags)
	index := 1
	for i := 0; i < connectionIDLen; i++ {
		wire[index+i] = byte(fh.ConnectionID >> (8 * (connectionIDLen - i - 1)))
	}
	index += connectionIDLen

	for i := 0; i < versionLen; i++ {
		wire[index+i] = byte(fh.Version >> (8 * (versionLen - i - 1)))
	}
	index += versionLen

	for i := 0; i < sequenceNumberLen; i++ {
		wire[index+i] = byte(fh.SequenceNumber >> (8 * (sequenceNumberLen - i - 1)))
	}
	index += sequenceNumberLen

	wire[index] = fh.PrivateFlags

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
	Type       byte
	StreamID   uint32
	Offset     uint64
	DataLength uint16
}

func NewStreamFrame(fin bool, streamID uint32, offset uint64, dataLength uint16) *StreamFrame {
	var frameType byte = 0x80
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
		frametype |= 0x14
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
	streamFrame := &StreamFrame{fh,
		frameType,
		streamID,
		offset,
		dataLength,
	}
	return streamFrame
}

func (frame *StreamFrame) Parse(data []byte) (err error) {
	frame.Type = data[0]
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

	var offset uint64 = 0
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
			frame.Offset |= uint64(data[index+i] << (8 * (3 - i)))
		}
		index += 4
	case frame.Type&0x1c == 0x10:
		for i := 0; i < 5; i++ {
			frame.Offset |= uint64(data[index+i] << (8 * (4 - i)))
		}
		index += 5
	case frame.Type&0x1c == 0x14:
		for i := 0; i < 6; i++ {
			frame.Offset |= uint64(data[index+i] << (8 * (5 - i)))
		}
		index += 6
	case frame.Type&0x1c == 0x18:
		for i := 0; i < 7; i++ {
			frame.Offset |= uint64(data[index+i] << (8 * (6 - i)))
		}
		index += 7
	case frame.Type&0x1c == 0x1c:
		for i := 0; i < 8; i++ {
			frame.Offset |= uint64(data[index+i] << (8 * (7 - i)))
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
	DLEN := (frame.Type & 0x20 >> 5) * 2

	// streamID length
	SLEN := (frame.Type & 0x03) + 1

	// offset length
	OLEN := (frame.Type & 0x1c >> 2)
	if tmp > 0 {
		OLEN += 1
	}

	wire = make([]byte, 1+DLEN+SLEN+OLEN)
	wire[0] = frame.Type
	index := 1

	for i := 0; i < SLEN; i++ {
		wire[index+i] = byte(frame.StreamID >> (8 * (SLEN - i - 1)))
	}
	index += SLEN

	for i := 0; i < OLEN; i++ {
		wire[index+i] = byte(frame.Offset >> (8 * (OLEN - i - 1)))
	}
	index += OLEN

	if DLEN > 0 {
		wire[index] = byte(frame.DataLength >> 8)
		wire[index+1] = byte(frame.DataLength)
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
	Type              byte
	SentEntropy       byte
	LeastUnackedDelta uint64
}

func NewStopWaitingFrame(sentEntropy byte, leastUnackedDelta uint64) *StopWaiting {
	fh := &FrameHeader{} // temporaly
	stopWaitingFrame := &StopWaitingFrame{fh,
		StopWaitingFrameType,
		sentEntropy,
		leasetUnackedDelta,
	}
	return stopWaitingFrame
}

func (frame *StopWaitingFrame) Parse(data []byte) (err error) {
	frame.Type = data[0]
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
		frame.LeastUnackedDelta |= uint64(data[2+i] << (8 * (length - i - 1)))
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
	wire[0] = frame.Type
	wire[1] = frame.SentEntropy

	for i := 0; i < length; i++ {
		wire[2+i] = byte(frame.LeastUnackedDelta >> (8 * (length - i - 1)))
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
	Type     byte
	StreamID uint32
	Offset   uint64
}

func NewWindowUpdateFrame(streamID uint32, offset uint64) *WindowUpdateFrame {
	fh := &WindowUpdateFrame{} //temporaly
	windowUpdateFrame := &WindowUpdateFrame{fh,
		WindowUpdateFrameType,
		streamID,
		offset,
	}
	return
}

func (frame *WindowUpdateFrame) Parse(data []byte) (err error) {
	frame.Type = data[0]
	frame.StreamID = uint32(data[1]<<24 | data[2]<<16 | data[3]<<8 | data[4])
	for i := 0; i < 8; i++ {
		frame.Offset |= uint64(data[5+i] << (8 * (7 - i)))
	}
	return
}

func (frame *WindowUpdateFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 13)
	wire[0] = frame.Type
	for i := 0; i < 4; i++ {
		wire[1+i] = uint32(frame.StreamID >> (8 * (3 - i)))
	}
	for i := 0; i < 8; i++ {
		wire[5+i] = uint32(frame.Offset >> (8 * (7 - i)))
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
	Type     byte
	StreamID uint32
}

func NewBlockedFrame(streamID uint32) *BlockedFrame {
	fh := &FrameHeader{} //temporaly
	blockedFrame := &BlockedFrame{fh,
		BlockedFrameType,
		streamID,
	}
	return blockedFrame
}

func (frame *BlockedFrame) Parse(data []byte) (err error) {
	frame.Type = data[0]
	frame.StreamID = uint32(data[1]<<24 | data[2]<<16 | data[3]<<8 | data[4])
	return
}

func (frame *BlockedFrame) GetWire() (wire []byte, err error) {
	wire = make([]byte, 5)
	wire[0] = frame.Type
	for i := 0; i < 4; i++ {
		wire[1+i] = uint32(frame.StreamID >> (8 * (3 - i)))
	}

	return
}
