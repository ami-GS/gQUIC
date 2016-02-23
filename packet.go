package quic

import (
	"encoding/binary"
	"fmt"
)

const QUIC_VERSION = uint32('Q'<<24 | '0'<<16 | '2'<<8 | '5') // temporally

type Packet interface {
	GetWire() ([]byte, error)
	String() string
}

type PacketParser func(ph *PacketHeader, data []byte) (Packet, int)

var PacketParserMap = map[PacketType]PacketParser{
	VersionNegotiationPacketType: ParseVersionNegotiationPacket,
	FramePacketType:              ParseFramePacket,
	FECPacketType:                ParseFECPacket,
	PublicResetPacketType:        ParsePublicResetPacket,
}

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

func (f PublicFlagType) String() string {
	str := ""
	if f&CONTAIN_QUIC_VERSION == CONTAIN_QUIC_VERSION {
		str += "\tCONTAIN_QUIC_VERSION\n"
	}
	if f&PUBLIC_RESET == PUBLIC_RESET {
		str += "\tPUBLIC_RESET\n"
	}
	switch f & CONNECTION_ID_LENGTH_MASK {
	case CONNECTION_ID_LENGTH_8:
		str += "\tCONNECTION_ID_LENGTH_8\n"
	case CONNECTION_ID_LENGTH_4:
		str += "\tCONNECTION_ID_LENGTH_4\n"
	case CONNECTION_ID_LENGTH_1:
		str += "\tCONNECTION_ID_LENGTH_1\n"
	default:
		str += "\tOMIT_CONNECTION_ID\n"
	}
	switch f & SEQUENCE_NUMBER_LENGTH_MASK {
	case SEQUENCE_NUMBER_LENGTH_6:
		str += "\tSEQUENCE_NUMBER_LENGTH_6\n"
	case SEQUENCE_NUMBER_LENGTH_4:
		str += "\tSEQUENCE_NUMBER_LENGTH_4\n"
	case SEQUENCE_NUMBER_LENGTH_2:
		str += "\tSEQUENCE_NUMBER_LENGTH_2\n"
	case SEQUENCE_NUMBER_LENGTH_1:
		str += "\tSEQUENCE_NUMBER_LENGTH_1\n"
	}
	if len(str) > 0 {
		str = "\n" + str
	}
	return str
}

type PrivateFlagType byte

const (
	FLAG_ENTROPY   PrivateFlagType = 0x01
	FLAG_FEC_GROUP                 = 0x02
	FLAG_FEC                       = 0x04
)

func (f PrivateFlagType) String() string {
	str := ""
	if f&FLAG_ENTROPY == FLAG_ENTROPY {
		str += "\tFLAG_ENTROPY\n"
	}
	if f&FLAG_FEC_GROUP == FLAG_FEC_GROUP {
		str += "\tFLAG_FEC_GROUP\n"
	}
	if f&FLAG_FEC == FLAG_FEC {
		str += "\tFLAG_FEC\n"
	}
	if len(str) > 0 {
		str = "\n" + str
	}
	return str
}

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

func ParsePacketHeader(data []byte) (ph *PacketHeader, length int, err error) {
	ph = &PacketHeader{
		PublicFlags: PublicFlagType(data[0]),
	}
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

	if ph.Type != PublicResetPacketType {
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
	return ph, length, err
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
	if ph.Type != PublicResetPacketType {
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

func (ph *PacketHeader) String() string {
	return fmt.Sprintf("Packet Type=%s, PublicFlags={%s}, ConnectionID=%d, Version=%d, SequenceNumber=%d, PrivateFlags={%s}, FEC=%d\n", ph.Type.String(), ph.PublicFlags.String(), ph.ConnectionID, ph.Version, ph.SequenceNumber, ph.PrivateFlags.String(), ph.FEC)
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

func NewFramePacket(connectionID, sequenceNumber uint64) *FramePacket {
	ph := NewPacketHeader(FramePacketType, connectionID, 0, sequenceNumber, 0)
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

func ParseFECPacket(ph *PacketHeader, data []byte) (Packet, int) {
	packet := &FECPacket{
		PacketHeader: ph,
		Redundancy:   data, // TODO: clearify here
	}
	// TODO: not cool now
	return packet, len(data)
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

func (packet *FECPacket) String() string {
	return packet.PacketHeader.String() //TODO
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

func ParsePublicResetPacket(ph *PacketHeader, data []byte) (Packet, int) {
	packet := &PublicResetPacket{
		PacketHeader: ph,
		//Msg: // TODO: what todo here?
	}
	//packet.Msg.Parse(data)
	return packet, len(data)
}

func (packet *PublicResetPacket) GetWire() ([]byte, error) {
	// wire of Public Flags and Connection ID are extract from PacketHeader
	hWire, err := packet.PacketHeader.GetWire()
	msgWire, err := packet.Msg.GetWire()
	return append(hWire, msgWire...), err
}

func (packet *PublicResetPacket) String() string {
	return packet.PacketHeader.String() //TODO
}

func (packet *PublicResetPacket) AppendTagValue(tag QuicTag, value []byte) bool {
	return packet.Msg.AppendTagValue(tag, value)
}
