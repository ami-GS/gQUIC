package quic

import (
	"encoding/binary"
	"fmt"

	"github.com/ami-GS/gQUIC/utils"
)

type Packet interface {
	GetWire() ([]byte, error)
	GetConnectionID() uint64
	String() string
}

type PacketParser func(ph *PacketHeader, data []byte) (Packet, int)

var PacketParserMap = map[PacketType]PacketParser{
	VersionNegotiationPacketType: ParseVersionNegotiationPacket,
	FramePacketType:              ParseFramePacket,
	PublicResetPacketType:        ParsePublicResetPacket,
}

type PacketType byte

const (
	VersionNegotiationPacketType PacketType = iota
	FramePacketType
	PublicResetPacketType
)

func (pType PacketType) String() string {
	t := []string{
		"Version Negotiation",
		"Frame",
		"Public Reset",
	}
	return t[int(pType)]
}

type PublicFlagType byte

const (
	CONTAIN_QUIC_VERSION      PublicFlagType = 0x01
	PUBLIC_RESET                             = 0x02
	PRESENT_NONSE                            = 0x04
	CONNECTION_ID_LENGTH_8                   = 0x08
	OMIT_CONNECTION_ID                       = 0x00
	PACKET_NUMBER_LENGTH_MASK                = 0x30
	PACKET_NUMBER_LENGTH_6                   = 0x30
	PACKET_NUMBER_LENGTH_4                   = 0x20
	PACKET_NUMBER_LENGTH_2                   = 0x10
	PACKET_NUMBER_LENGTH_1                   = 0x00
	RESERVED_MULTIPATH                       = 0x40
	MUST_BE_ZERO                             = 0x80
)

func (f PublicFlagType) String() string {
	str := ""
	if f&CONTAIN_QUIC_VERSION == CONTAIN_QUIC_VERSION {
		str += "\tCONTAIN_QUIC_VERSION\n"
	}
	if f&PUBLIC_RESET == PUBLIC_RESET {
		str += "\tPUBLIC_RESET\n"
	}
	if f&PRESENT_NONSE == PRESENT_NONSE {
		str += "\tPRESENT_NONSE"
	}
	if f&CONNECTION_ID_LENGTH_8 == CONNECTION_ID_LENGTH_8 {
		str += "\tCONNECTION_ID_LENGTH_8"
	} else {
		str += "\tCONNECTION_ID_NOT_PRESENT"
	}
	switch f & PACKET_NUMBER_LENGTH_MASK {
	case PACKET_NUMBER_LENGTH_6:
		str += "\tPACKET_NUMBER_LENGTH_6\n"
	case PACKET_NUMBER_LENGTH_4:
		str += "\tPACKET_NUMBER_LENGTH_4\n"
	case PACKET_NUMBER_LENGTH_2:
		str += "\tPACKET_NUMBER_LENGTH_2\n"
	case PACKET_NUMBER_LENGTH_1:
		str += "\tPACKET_NUMBER_LENGTH_1\n"
	}
	if len(str) > 0 {
		str = "\n" + str
	}
	return str
}

// Packet Header
/*
     0        1        2        3        4            8
+--------+--------+--------+--------+--------+---    ---+
| Public |    Connection ID (0 or 64)    ...            | ->
|Flags(8)|      (variable length)                       |
+--------+--------+--------+--------+--------+---    ---+

     9       10       11        12
+--------+--------+--------+--------+
|      QUIC Version (32)            | ->
|         (optional)                |
+--------+--------+--------+--------+


    13       14       15        16      17       18       19       20
+--------+--------+--------+--------+--------+--------+--------+--------+
|                        Diversification Nonce                          | ->
|                              (optional)                               |
+--------+--------+--------+--------+--------+--------+--------+--------+

    21       22       23        24      25       26       27       28
+--------+--------+--------+--------+--------+--------+--------+--------+
|                   Diversification Nonce Continued                     | ->
|                              (optional)                               |
+--------+--------+--------+--------+--------+--------+--------+--------+

    29       30       31        32      33       34       35       36
+--------+--------+--------+--------+--------+--------+--------+--------+
|                   Diversification Nonce Continued                     | ->
|                              (optional)                               |
+--------+--------+--------+--------+--------+--------+--------+--------+

    37       38       39        40      41       42       43       44
+--------+--------+--------+--------+--------+--------+--------+--------+
|                   Diversification Nonce Continued                     | ->
|                              (optional)                               |
+--------+--------+--------+--------+--------+--------+--------+--------+


    45      46       47        48       49       50
+--------+--------+--------+--------+--------+--------+
|           Packet Number (8, 16, 32, or 48)          |
|                  (variable length)                  |
+--------+--------+--------+--------+--------+--------+
*/

type PacketHeader struct {
	Type          PacketType
	PublicFlags   PublicFlagType
	ConnectionID  uint64
	Nonse         []uint8 // 0(nil) or 32
	Versions      []uint32
	PacketNumber  uint64
	RegularPacket bool
}

func NewPacketHeader(packetType PacketType, connectionID uint64, versions []uint32, packetNumber uint64, nonse []uint8) *PacketHeader {
	var publicFlags PublicFlagType
	regularPacket := false
	switch packetType {
	case PublicResetPacketType:
		publicFlags |= PUBLIC_RESET
	case VersionNegotiationPacketType:
		publicFlags |= CONTAIN_QUIC_VERSION
	default:
		regularPacket = true
	}

	// This must be set in all packets until negotiated
	//　to a different value for a given direction
	// if not negotiated {
	publicFlags |= CONNECTION_ID_LENGTH_8
	if nonse != nil {
		publicFlags |= PRESENT_NONSE
	}
	if packetType == FramePacketType {
		switch {
		case packetNumber <= 0xff:
			publicFlags |= PACKET_NUMBER_LENGTH_1
		case packetNumber <= 0xffff:
			publicFlags |= PACKET_NUMBER_LENGTH_2
		case packetNumber <= 0xffffffff:
			publicFlags |= PACKET_NUMBER_LENGTH_4
		case packetNumber <= 0xffffffffffff:
			publicFlags |= PACKET_NUMBER_LENGTH_6
		}

		// version negotiation packet is still considering?
		// others indicate frame packet
	} else {
		publicFlags |= PACKET_NUMBER_LENGTH_1
	}

	if !regularPacket {
		packetNumber = 0
		// TODO: emit warnning, packet number cannnot be set
	}
	ph := &PacketHeader{
		Type:          packetType,
		PublicFlags:   publicFlags,
		ConnectionID:  connectionID,
		Nonse:         nonse,
		Versions:      versions,
		PacketNumber:  packetNumber,
		RegularPacket: regularPacket,
	}
	return ph
}

func ParsePacketHeader(data []byte, fromServer bool) (ph *PacketHeader, length int, err error) {
	ph = &PacketHeader{
		PublicFlags:   PublicFlagType(data[0]),
		RegularPacket: false,
		Type:          FramePacketType,
	}

	if ph.PublicFlags&PUBLIC_RESET == PUBLIC_RESET {
		ph.Type = PublicResetPacketType
	} else if ph.PublicFlags&CONTAIN_QUIC_VERSION == CONTAIN_QUIC_VERSION {
		if fromServer {
			ph.Type = VersionNegotiationPacketType
		} else {
			// Regular Packet with QUIC Version present in header
			ph.RegularPacket = true
		}
	} else {
		ph.RegularPacket = true // Regular Packet
	}
	length = 1
	if ph.PublicFlags&CONNECTION_ID_LENGTH_8 == CONNECTION_ID_LENGTH_8 {
		ph.ConnectionID = binary.BigEndian.Uint64(data[1:9])
		length += 8
	}
	if ph.PublicFlags&PRESENT_NONSE == PRESENT_NONSE {
		copy(ph.Nonse, data[length:length+32])
		length += 32
	}

	if ph.RegularPacket {
		// TODO: parse sequence number
		switch ph.PublicFlags & PACKET_NUMBER_LENGTH_MASK {
		case PACKET_NUMBER_LENGTH_6:
			ph.PacketNumber = binary.BigEndian.Uint64(data[length:])
			length += 6
		case PACKET_NUMBER_LENGTH_4:
			ph.PacketNumber = uint64(data[length])<<24 | uint64(data[length+1])<<16 | uint64(data[length+2])<<8 | uint64(data[length+3])
			length += 4
		case PACKET_NUMBER_LENGTH_2:
			ph.PacketNumber = uint64(data[length])<<8 | uint64(data[length+1])
			length += 2
		case PACKET_NUMBER_LENGTH_1:
			ph.PacketNumber = uint64(data[length])
			length++
		}
	}

	if ph.PublicFlags&CONTAIN_QUIC_VERSION == CONTAIN_QUIC_VERSION {
		ph.Versions = append(ph.Versions, binary.BigEndian.Uint32(data[length:]))
		length += 4
		if ph.Type == VersionNegotiationPacketType {
			for length < len(data) {
				ph.Versions = append(ph.Versions, binary.BigEndian.Uint32(data[length:]))
				length += 4
			}
		}
	}

	return ph, length, err
}

func (ph *PacketHeader) GetWire() (wire []byte, err error) {
	// confirm variable length
	cIDLen := 0
	if ph.PublicFlags&CONNECTION_ID_LENGTH_8 == CONNECTION_ID_LENGTH_8 {
		cIDLen = 8
	}

	vLen := 0
	if ph.PublicFlags&CONTAIN_QUIC_VERSION == CONTAIN_QUIC_VERSION {
		vLen = 4 * len(ph.Versions)
	}

	nonseLen := 0
	if ph.PublicFlags&PRESENT_NONSE == PRESENT_NONSE {
		nonseLen = 32
	}

	pNumLen := 0
	if ph.RegularPacket {
		switch ph.PublicFlags & PACKET_NUMBER_LENGTH_MASK {
		case PACKET_NUMBER_LENGTH_6:
			pNumLen = 6
		case PACKET_NUMBER_LENGTH_4:
			pNumLen = 4
		case PACKET_NUMBER_LENGTH_2:
			pNumLen = 2
		case PACKET_NUMBER_LENGTH_1:
			pNumLen = 1
		}
	}

	wire = make([]byte, 1+cIDLen+vLen+pNumLen+nonseLen)
	wire[0] = byte(ph.PublicFlags)
	index := 1
	index += utils.MyPutUint64(wire[index:], ph.ConnectionID, cIDLen)

	if vLen > 0 {
		for _, v := range ph.Versions {
			binary.BigEndian.PutUint32(wire[index:], v)
			index += vLen
		}
	}

	if nonseLen > 0 {
		copy(wire[index:], ph.Nonse)
		index += nonseLen
	}

	index += utils.MyPutUint64(wire[index:], ph.PacketNumber, pNumLen)

	return
}

func (ph *PacketHeader) String() string {
	return fmt.Sprintf("Packet Type=%s, PublicFlags={%s}, ConnectionID=%d, Version=%d, PacketNumber=%d\n", ph.Type.String(), ph.PublicFlags.String(), ph.ConnectionID, ph.Versions, ph.PacketNumber)
}

/*
0        1        2        3        4        5        6        7       8
+--------+--------+--------+--------+--------+--------+--------+--------+--------+
| Public |    Connection ID (64)                                                 | ->
|Flags(8)|                                                                       |
+--------+--------+--------+--------+--------+--------+--------+--------+--------+
	9       10       11        12       13      14       15       16       17
+--------+--------+--------+--------+--------+--------+--------+--------+---...--+
|      1st QUIC version supported   |     2nd QUIC version supported    |   ...
|      by server (32)               |     by server (32)                |
+--------+--------+--------+--------+--------+--------+--------+--------+---...--+
*/

type VersionNegotiationPacket struct {
	*PacketHeader
}

func NewVersionNegotiationPacket(connectionID uint64, versions []uint32) *VersionNegotiationPacket {
	ph := NewPacketHeader(VersionNegotiationPacketType, connectionID, versions, 0, nil)
	packet := &VersionNegotiationPacket{
		PacketHeader: ph,
	}
	return packet
}

func ParseVersionNegotiationPacket(ph *PacketHeader, data []byte) (Packet, int) {
	packet := &VersionNegotiationPacket{
		PacketHeader: ph,
	}
	// TODO: there are no detail on specification stil
	return packet, len(data)
}

func (packet *VersionNegotiationPacket) GetWire() (wire []byte, err error) {
	// TODO: there are no detail on specification stil
	hWire, _ := packet.PacketHeader.GetWire()
	return append(hWire, wire...), err
}

func (packet *VersionNegotiationPacket) GetConnectionID() uint64 {
	return packet.ConnectionID
}

func (packet *VersionNegotiationPacket) String() string {
	return packet.PacketHeader.String() // TODO
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

func NewFramePacket(connectionID, packetNumber uint64) *FramePacket {
	ph := NewPacketHeader(FramePacketType, connectionID, nil, packetNumber, nil)
	packet := &FramePacket{
		PacketHeader: ph,
		Frames:       []*Frame{},
		RestSize:     MTU,
	}
	return packet
}

func ParseFramePacket(ph *PacketHeader, data []byte) (Packet, int) {
	packet := &FramePacket{
		PacketHeader: ph,
		Wire:         data,
		DataSize:     uint16(len(data)),
		RestSize:     MTU - uint16(len(data)),
	}
	idx := 0
	dataLen := len(data)
	for idx < dataLen {
		f := FrameParserMap[FrameType(data[idx])]
		if f == nil {
			if data[idx]&StreamFrameType == StreamFrameType {
				f = FrameParserMap[FrameType(data[idx]&0x80)]
			} else if data[idx]&AckFrameType == AckFrameType {
				f = FrameParserMap[FrameType(data[idx]&0x40)]
			} else if data[idx]&CongestionFeedbackFrameType == CongestionFeedbackFrameType {
				f = FrameParserMap[FrameType(data[idx]&0x20)]
			}
		}
		frame, nxt := f(packet, data[idx:])
		packet.Frames = append(packet.Frames, &frame)
		idx += nxt
	}
	return packet, idx
}

func (packet *FramePacket) GetWire() ([]byte, error) {
	hWire, err := packet.PacketHeader.GetWire()
	if len(packet.Wire) == 0 {
		for _, f := range packet.Frames {
			wire, _ := (*f).GetWire()
			packet.Wire = append(packet.Wire, wire...)
		}
	}
	return append(hWire, packet.Wire...), err // temporally
}

func (packet *FramePacket) GetConnectionID() uint64 {
	return packet.ConnectionID
}

func (packet *FramePacket) PushBack(frame Frame) bool {
	wire, _ := frame.GetWire()
	dataSize := uint16(len(wire))

	if packet.DataSize+dataSize <= MTU {
		packet.Frames = append(packet.Frames, &frame)
		packet.Wire = append(packet.Wire, wire...)
		packet.DataSize += dataSize
		packet.RestSize -= dataSize
		//frame.SetPacket(packet) // TODO: is this cool?
		return true
	}
	return false
}

func (packet *FramePacket) String() (str string) {
	str = packet.PacketHeader.String()
	for _, frame := range packet.Frames {
		str += "\t" + (*frame).String() + "\n"
	}
	return
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
	ph := NewPacketHeader(PublicResetPacketType, connectionID, nil, 0, nil)
	packet := &PublicResetPacket{
		PacketHeader: ph,
		Msg:          NewMessage(PRST),
	}
	return packet
}

func ParsePublicResetPacket(ph *PacketHeader, data []byte) (Packet, int) {
	packet := &PublicResetPacket{
		PacketHeader: ph,
		Msg:          &Message{},
	}
	packet.Msg.Parse(data)
	return packet, len(data)
}

func (packet *PublicResetPacket) GetWire() ([]byte, error) {
	// wire of Public Flags and Connection ID are extract from PacketHeader
	hWire, err := packet.PacketHeader.GetWire()
	msgWire, err := packet.Msg.GetWire()
	return append(hWire, msgWire...), err
}

func (packet *PublicResetPacket) GetConnectionID() uint64 {
	return packet.ConnectionID
}

func (packet *PublicResetPacket) String() string {
	return packet.PacketHeader.String() //TODO
}

func (packet *PublicResetPacket) AppendTagValue(tag QuicTag, value []byte) bool {
	return packet.Msg.AppendTagValue(tag, value)
}
