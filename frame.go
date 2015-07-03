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

// Frame Header
/*
+--------+--------+--------+--------+--------+---    ---+
 Public |    Connection ID (0, 8, 32, or 64)    ...    | ->
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
