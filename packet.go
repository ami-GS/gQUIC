package quic

const QUIC_VERSION = uint32('Q'<<24 | '0'<<16 | '2'<<8 | '5') // temporally

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

// Packet Header
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

type PacketHeader struct {
	PublicFlags    PublicFlagType
	ConnectionID   uint64
	Version        uint32
	SequenceNumber uint64
	PrivateFlags   PrivateFlagType
	FEC            byte
}

func NewPacketHeader(connectionID uint64, version uint32, sequenceNumber uint64, privateFlags PrivateFlagType, fec byte) *PacketHeader {
	var publicFlags PublicFlagType = 0x00
	switch {
	case connectionID <= 0:
		publicFlags |= OMIT_CONNECTION_ID
	case connectionID <= 0xff:
		publicFlags |= CONNECTION_ID_LENGTH_1
	case connectionID <= 0xffffffff:
		publicFlags |= CONNECTION_ID_LENGTH_4
	case connectionID <= 0xffffffffffffffff:
		// This indicate public reset packet
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

	// version negotiation packet is still considering?
	// private flags == FLAG_FEC indicate FEC packet
	// others indicate frame packet

	ph := &PacketHeader{
		PublicFlags:    publicFlags,
		ConnectionID:   connectionID,
		Version:        version,
		SequenceNumber: sequenceNumber,
		PrivateFlags:   privateFlags,
		FEC:            fec,
	}
	return ph
}

func (ph *PacketHeader) Parse(data []byte) (err error) {
	index := 0
	ph.PublicFlags = PublicFlagType(data[index])

	switch ph.PublicFlags & CONNECTION_ID_LENGTH_MASK {
	case CONNECTION_ID_LENGTH_8:
		ph.ConnectionID = uint64(data[1]<<56 | data[2]<<48 | data[3]<<40 | data[4]<<32 | data[5]<<24 | data[6]<<16 | data[7]<<8 | data[8])
		index = 9
	case CONNECTION_ID_LENGTH_4:
		ph.ConnectionID = uint64(data[1]<<24 | data[2]<<16 | data[3]<<8 | data[4])
		index = 5
	case CONNECTION_ID_LENGTH_1:
		ph.ConnectionID = uint64(data[1])
		index = 2
	case OMIT_CONNECTION_ID:
		ph.ConnectionID = 0 // omitted
		index = 1

	}

	if ph.PublicFlags&CONTAIN_QUIC_VERSION == CONTAIN_QUIC_VERSION {
		ph.Version = uint32(data[index]<<24 | data[index+1]<<16 | data[index+2]<<8 | data[index+3])
		index += 4
	}

	// TODO: parse sequence number
	switch ph.PublicFlags & SEQUENCE_NUMBER_LENGTH_MASK {
	case SEQUENCE_NUMBER_LENGTH_6:
		ph.SequenceNumber = uint64(data[index]<<40 | data[index+1]<<32 | data[index+2]<<24 | data[index+3]<<16 | data[index+4]<<8 | data[index+5])
		index += 6
	case SEQUENCE_NUMBER_LENGTH_4:
		ph.SequenceNumber = uint64(data[index]<<24 | data[index+1]<<16 | data[index+2]<<8 | data[index+3])
		index += 4
	case SEQUENCE_NUMBER_LENGTH_2:
		ph.SequenceNumber = uint64(data[index]<<8 | data[index+1])
		index += 2
	case SEQUENCE_NUMBER_LENGTH_1:
		ph.SequenceNumber = uint64(data[index])
		index += 1
	}

	ph.PrivateFlags = PrivateFlagType(data[index])
	if ph.PrivateFlags&FLAG_ENTROPY == FLAG_ENTROPY {
		// TODO: ?
	}
	if ph.PrivateFlags&FLAG_FEC_GROUP == FLAG_FEC_GROUP {
		ph.FEC = data[index]
	}
	if ph.PrivateFlags&FLAG_FEC == FLAG_FEC {
		//TODO: FEC packet
	}

	return
}

func (ph *PacketHeader) GetWire() (wire []byte, err error) {
	// confirm variable length
	connectionIDLen := 0
	switch ph.PublicFlags & CONNECTION_ID_LENGTH_MASK {
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
	if ph.PublicFlags&0x01 > 0 {
		versionLen = 4
	}

	sequenceNumberLen := 1
	switch ph.PublicFlags & SEQUENCE_NUMBER_LENGTH_MASK {
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
	if ph.PrivateFlags&FLAG_ENTROPY == FLAG_ENTROPY {
		// TODO: ?
	}
	if ph.PrivateFlags&FLAG_FEC_GROUP == FLAG_FEC_GROUP {
		fecLen = 1
	}
	if ph.PrivateFlags&FLAG_FEC == FLAG_FEC {
		//TODO: FEC packet
	}

	// pack to wire
	wire = make([]byte, 1+connectionIDLen+versionLen+sequenceNumberLen+1+fecLen)
	wire[0] = byte(ph.PublicFlags)
	index := 1
	for i := 0; i < connectionIDLen; i++ {
		wire[index+i] = byte(ph.ConnectionID >> byte(8*(connectionIDLen-i-1)))
	}
	index += connectionIDLen

	for i := 0; i < versionLen; i++ {
		wire[index+i] = byte(ph.Version >> byte(8*(versionLen-i-1)))
	}
	index += versionLen

	for i := 0; i < sequenceNumberLen; i++ {
		wire[index+i] = byte(ph.SequenceNumber >> byte(8*(sequenceNumberLen-i-1)))
	}
	index += sequenceNumberLen

	wire[index] = byte(ph.PrivateFlags)

	if fecLen > 0 {
		wire[index+1] = ph.FEC
	}

	return
}

func (ph *PacketHeader) String() (str string) {
	str = "Packet Header" // temporally
	return
}

type VersionNegotiationPacket struct {
	*PacketHeader
	Version uint32 //?
}

/*
   +--------+---...---+--------+---...---+
   | Type   | Payload | Type   | Payload |
   +--------+---...---+--------+---...---+
*/
type FramePacket struct {
	*PacketHeader
	Frames []Frame
}

func NewFramePacket() *FramePacket {
	ph := &PacketHeader{} //temporally
	packet := &FramePacket{
		PacketHeader: ph,
		Frames:       []Frame{},
	}
	return packet
}

func (packet *FramePacket) Parse(data []byte) (idx int, err error) {
	var frame Frame
	for idx < len(data) {
		switch FrameType(data[idx]) {
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
			if data[idx]&StreamFrameType == StreamFrameType {
				frame = &StreamFrame{}
			} else if data[idx]&AckFrameType == AckFrameType {
				frame = &AckFrame{}
			} else if data[idx]&CongestionFeedbackFrameType == CongestionFeedbackFrameType {
				//frame = &CongestionFeedbackFrame{}
			}
		}
		nxt, _ := frame.Parse(data[idx:])
		idx += nxt
		packet.Frames = append(packet.Frames, frame)
	}
	return
}

func (packet *FramePacket) GetWire() (wire []byte, err error) {
	for _, frame := range packet.Frames {
		wireTmp, _ := frame.GetWire()
		wire = append(wire, wireTmp...)
	}
	return
}

func (packet *FramePacket) String() (str string) {
	str = packet.PacketHeader.String()
	str += "Frame Packet\n"
	for _, frame := range packet.Frames {
		str += frame.String() + "\n"
	}
	return
}

/*
   +-----...----+
   | Redundancy |
   +-----...----+
*/
type FECPacket struct {
	*PacketHeader
	Redundancy []byte
}

/*
        0        1        2        3        4         8
   +--------+--------+--------+--------+--------+--   --+
   | Public |    Connection ID (64)                ...  | ->
   |Flags(8)|                                           |
   +--------+--------+--------+--------+--------+--   --+
        9       10       11        12       13      14
   +--------+--------+--------+--------+--------+--------+---
   |      Quic Tag (32)                |  Tag value map      ... ->
   |         (PRST)                    |  (variable length)
   +--------+--------+--------+--------+--------+--------+---
*/
type PublicResetPacket struct {
	*PacketHeader
	Tag         QuicTag
	TagValueMap uint64 // ?
}

func NewPublicResetPacket(tag QuicTag, tagValue uint64) *PublicResetPacket {
	//ph := NewPacketHeader(over 64 biy connectionID, 0?, PrivateFlags(0)?, 0?)
	ph := &PacketHeader{} //temporally
	packet := &PublicResetPacket{
		PacketHeader: ph,
		Tag:          tag,
		TagValueMap:  tagValue,
	}
	return packet
}

func (packet *PublicResetPacket) Parse(data []byte) (err error) {
	packet.Tag = QuicTag(data[0]<<24 | data[1]<<16 | data[2]<<8 | data[3])
	for i := 0; i < 8; i++ {
		packet.TagValueMap |= uint64(data[4+i] << byte(8*(7-i)))
	}
	return
}

func (packet *PublicResetPacket) GetWire() (wire []byte, err error) {
	// wire of Public Flags and Connection ID are extract from PacketHeader
	wire = make([]byte, 12)
	for i := 0; i < 4; i++ {
		wire[i] = byte(packet.Tag >> byte(8*(3-i)))
	}
	for i := 0; i < 8; i++ {
		wire[4+i] = byte(packet.TagValueMap >> byte(8*(7-i)))
	}
	return
}
