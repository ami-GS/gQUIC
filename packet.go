package quic

import (
	"encoding/binary"
	//"fmt"
)

const QUIC_VERSION = uint32('Q'<<24 | '0'<<16 | '2'<<8 | '5') // temporally

type PacketType byte

const (
	VersionNegotiationPacketType PacketType = iota
	FramePacketType
	FECPacketType
	PublicResetPacketType
)

func (pType PacketType) String() string {
	t := []string{
		"Version Negotiation",
		"Frame",
		"FEC",
		"Public Reset",
	}
	return t[int(pType)]
}

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
	Type           PacketType
	PublicFlags    PublicFlagType
	ConnectionID   uint64
	Version        uint32
	SequenceNumber uint64
	PrivateFlags   PrivateFlagType
	FEC            byte
}

func NewPacketHeader(packetType PacketType, connectionID uint64, version uint32, sequenceNumber uint64, fec byte) *PacketHeader {

	var publicFlags PublicFlagType
	var privateFlags PrivateFlagType
	switch packetType {
	case PublicResetPacketType:
		publicFlags |= PUBLIC_RESET
	case VersionNegotiationPacketType:
		publicFlags |= CONTAIN_QUIC_VERSION
	case FECPacketType:
		privateFlags |= FLAG_FEC
	case FramePacketType:
		// do nothing
	}

	if packetType != PublicResetPacketType {
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
	} else {
		publicFlags |= CONNECTION_ID_LENGTH_8
	}

	// TODO: currently, SequenceNumber changes in FECPacket.AppendFramePacket,
	// so that here should be in GetWire(). right?
	if packetType == FramePacketType {
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
	} else {
		publicFlags |= SEQUENCE_NUMBER_LENGTH_1
	}

	ph := &PacketHeader{
		Type:           packetType,
		PublicFlags:    publicFlags,
		ConnectionID:   connectionID,
		Version:        version,
		SequenceNumber: sequenceNumber,
		PrivateFlags:   privateFlags,
		FEC:            fec,
	}
	return ph
}

func (ph *PacketHeader) Parse(data []byte) (length int, err error) {
	ph.PublicFlags = PublicFlagType(data[length])
	switch ph.PublicFlags & 0x03 {
	case CONTAIN_QUIC_VERSION:
		ph.Type = VersionNegotiationPacketType
	case PUBLIC_RESET:
		ph.Type = PublicResetPacketType
	default:
		ph.Type = FramePacketType
		// NOTICE: FECPacketType is evaluated later
	}

	switch ph.PublicFlags & CONNECTION_ID_LENGTH_MASK {
	case CONNECTION_ID_LENGTH_8:
		ph.ConnectionID = binary.BigEndian.Uint64(data[1:])
		length = 9
	case CONNECTION_ID_LENGTH_4:
		ph.ConnectionID = uint64(data[1])<<24 | uint64(data[2])<<16 | uint64(data[3])<<8 | uint64(data[4])
		length = 5
	case CONNECTION_ID_LENGTH_1:
		ph.ConnectionID = uint64(data[1])
		length = 2
	case OMIT_CONNECTION_ID:
		ph.ConnectionID = 0 // omitted
		length = 1
	}

	if ph.Type == PublicResetPacketType {
		// Public Reset Packet doesn't use sequence Number and private flags,
		// but the packet has these two bytes
		length += 2
	} else {
		if ph.Type == VersionNegotiationPacketType {
			ph.Version = binary.BigEndian.Uint32(data[length:])
			length += 4
		}

		// TODO: parse sequence number
		switch ph.PublicFlags & SEQUENCE_NUMBER_LENGTH_MASK {
		case SEQUENCE_NUMBER_LENGTH_6:
			ph.SequenceNumber = binary.BigEndian.Uint64(data[length:])
			length += 6
		case SEQUENCE_NUMBER_LENGTH_4:
			ph.SequenceNumber = uint64(data[length])<<24 | uint64(data[length+1])<<16 | uint64(data[length+2])<<8 | uint64(data[length+3])
			length += 4
		case SEQUENCE_NUMBER_LENGTH_2:
			ph.SequenceNumber = uint64(data[length])<<8 | uint64(data[length+1])
			length += 2
		case SEQUENCE_NUMBER_LENGTH_1:
			ph.SequenceNumber = uint64(data[length])
			length += 1
		}

		ph.PrivateFlags = PrivateFlagType(data[length])
		length += 1
		if ph.PrivateFlags&FLAG_ENTROPY == FLAG_ENTROPY {
			// TODO: ?
		}
		if ph.PrivateFlags&FLAG_FEC_GROUP == FLAG_FEC_GROUP {
			ph.FEC = data[length]
			length += 1
		}
		if ph.PrivateFlags&FLAG_FEC == FLAG_FEC {
			ph.Type = FECPacketType
			//TODO: FEC packet
		}
	}
	return length, err
}

func (ph *PacketHeader) GetWire() (wire []byte, err error) {
	// confirm variable length
	cIDLen := 0
	switch ph.PublicFlags & CONNECTION_ID_LENGTH_MASK {
	case CONNECTION_ID_LENGTH_8:
		cIDLen = 8
	case CONNECTION_ID_LENGTH_4:
		cIDLen = 4
	case CONNECTION_ID_LENGTH_1:
		cIDLen = 1
	case OMIT_CONNECTION_ID:
		//pass
	}

	vLen := 0
	if ph.Type == VersionNegotiationPacketType {
		vLen = 4
	}

	sNumLen := 0
	switch ph.PublicFlags & SEQUENCE_NUMBER_LENGTH_MASK {
	case SEQUENCE_NUMBER_LENGTH_6:
		sNumLen = 6
	case SEQUENCE_NUMBER_LENGTH_4:
		sNumLen = 4
	case SEQUENCE_NUMBER_LENGTH_2:
		sNumLen = 2
	case SEQUENCE_NUMBER_LENGTH_1:
		sNumLen = 1
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
	wire = make([]byte, 1+cIDLen+vLen+sNumLen+1+fecLen)
	wire[0] = byte(ph.PublicFlags)
	index := 1
	for i := 0; i < cIDLen; i++ {
		wire[index+i] = byte(ph.ConnectionID >> byte(8*(cIDLen-i-1)))
	}
	index += cIDLen

	if vLen > 0 {
		binary.BigEndian.PutUint32(wire[index:], ph.Version)
		index += vLen
	}

	for i := 0; i < sNumLen; i++ {
		wire[index+i] = byte(ph.SequenceNumber >> byte(8*(sNumLen-i-1)))
	}
	index += sNumLen

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

func NewVersionNegotiationPacket(connectionID, sequenceNumber uint64, version uint32) *VersionNegotiationPacket {
	ph := NewPacketHeader(VersionNegotiationPacketType, connectionID, version, sequenceNumber, 0)
	packet := &VersionNegotiationPacket{
		PacketHeader: ph,
		Version:      version,
	}
	return packet
}

func (packet *VersionNegotiationPacket) Parse(data []byte) (length int, err error) {
	// TODO: there are no detail on specification stil
	return
}

func (packet *VersionNegotiationPacket) GetWire() (wire []byte, err error) {
	// TODO: there are no detail on specification stil
	hWire, _ := packet.PacketHeader.GetWire()
	return append(hWire, wire...), err
}

/*
   +--------+---...---+--------+---...---+
   | Type   | Payload | Type   | Payload |
   +--------+---...---+--------+---...---+
*/
type FramePacket struct {
	*PacketHeader
	Frames   []*Frame
	Wire     []byte
	DataSize uint16
	RestSize uint16
}

func NewFramePacket(connectionID, sequenceNumber uint64) *FramePacket {
	ph := NewPacketHeader(FramePacketType, connectionID, 0, sequenceNumber, 0)
	packet := &FramePacket{
		PacketHeader: ph,
		Frames:       []*Frame{},
		RestSize:     MTU,
	}
	return packet
}

func (packet *FramePacket) Parse(data []byte) (idx int, err error) {
	for idx < len(data) {
		var frame Frame
		switch FrameType(data[idx]) {
		case PaddingFrameType:
			frame = &PaddingFrame{FramePacket: packet}
		case RstStreamFrameType:
			frame = &RstStreamFrame{FramePacket: packet}
		case ConnectionCloseFrameType:
			frame = &ConnectionCloseFrame{FramePacket: packet}
		case GoAwayFrameType:
			frame = &GoAwayFrame{FramePacket: packet}
		case WindowUpdateFrameType:
			frame = &WindowUpdateFrame{FramePacket: packet}
		case BlockedFrameType:
			frame = &BlockedFrame{FramePacket: packet}
		case StopWaitingFrameType:
			frame = &StopWaitingFrame{FramePacket: packet}
		case PingFrameType:
			frame = &PingFrame{FramePacket: packet}
		default:
			if data[idx]&StreamFrameType == StreamFrameType {
				frame = &StreamFrame{FramePacket: packet}
			} else if data[idx]&AckFrameType == AckFrameType {
				frame = &AckFrame{FramePacket: packet}
			} else if data[idx]&CongestionFeedbackFrameType == CongestionFeedbackFrameType {
				//frame = &CongestionFeedbackFrame{}
			}
		}
		nxt, _ := frame.Parse(data[idx:])
		idx += nxt
		packet.Frames = append(packet.Frames, &frame)
	}
	return
}

func (packet *FramePacket) GetWire() ([]byte, error) {
	hWire, err := packet.PacketHeader.GetWire()
	return append(hWire, packet.Wire...), err // temporally
}

func (packet *FramePacket) PushBack(frame *Frame) bool {
	wire, _ := (*frame).GetWire()
	dataSize := uint16(len(wire))
	if packet.DataSize+dataSize <= MTU {
		packet.Frames = append(packet.Frames, frame)
		packet.Wire = append(packet.Wire, wire...)
		packet.DataSize += dataSize
		packet.RestSize -= dataSize
		return true
	}
	return false
}

func (packet *FramePacket) String() (str string) {
	str = packet.PacketHeader.String()
	str += "Frame Packet\n"
	for _, frame := range packet.Frames {
		str += "\t" + (*frame).String() + "\n"
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
	FECGroup   []*FramePacket
	Redundancy []byte
}

func NewFECPacket(firstPacket *FramePacket) *FECPacket {
	// TODO: is fec correct?
	// zero origin?
	// I guess byte length of sequence number in header should be fixed
	ph := NewPacketHeader(FECPacketType, firstPacket.ConnectionID, 0,
		firstPacket.SequenceNumber+1, 0)
	// TODO: bad performance same as below in UpdateRedundancy()
	// and suspicious because length of sequence Number might change.
	hWire, _ := ph.GetWire()
	redundancyLen := MTU - len(hWire)

	packet := &FECPacket{
		PacketHeader: ph,
		FECGroup:     []*FramePacket{firstPacket},
		Redundancy:   make([]byte, redundancyLen),
	}
	return packet
}

func (packet *FECPacket) Parse(data []byte) (length int, err error) {
	packet.Redundancy = data // TODO: clearify here
	return
}

func (packet *FECPacket) GetWire() (wire []byte, err error) {
	hWire, err := packet.PacketHeader.GetWire()
	return append(hWire, packet.Redundancy...), err
}

func (packet *FECPacket) AppendFramePacket(nextPacket *FramePacket) {
	nextPacket.FEC = byte(len(packet.FECGroup))
	packet.FECGroup = append(packet.FECGroup, nextPacket)
	packet.SequenceNumber += 1 //suspicious
	packet.UpdateRedundancy(nextPacket)
}

func (packet *FECPacket) UpdateRedundancy(nextPacket *FramePacket) {
	// TODO: call GetWire() cause bad performance, wire should be buffered
	wire, _ := nextPacket.GetWire()
	// TODO: check: len of wire and Redunduncy might same
	for i := 0; i < len(wire); i++ {
		packet.Redundancy[i] ^= wire[i]
	}
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
	Msg *Message
}

func NewPublicResetPacket(connectionID uint64) *PublicResetPacket {
	ph := NewPacketHeader(PublicResetPacketType, connectionID, 0, 0, 0)
	packet := &PublicResetPacket{
		PacketHeader: ph,
		Msg:          NewMessage(PRST),
	}
	return packet
}

func (packet *PublicResetPacket) Parse(data []byte) (err error) {
	packet.Msg.Parse(data)
	return
}

func (packet *PublicResetPacket) GetWire() ([]byte, error) {
	// wire of Public Flags and Connection ID are extract from PacketHeader
	hWire, err := packet.PacketHeader.GetWire()
	msgWire, err := packet.Msg.GetWire()
	return append(hWire, msgWire...), err
}

func (packet *PublicResetPacket) AppendTagValue(tag QuicTag, value []byte) bool {
	return packet.Msg.AppendTagValue(tag, value)
}
