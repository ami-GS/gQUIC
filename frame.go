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
