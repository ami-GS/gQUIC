package quiclatest

import (
	"encoding/binary"
)

type PacketParser func(data []byte) (p Packet, length int, err error)

var LongHeaderPacketParserMap = map[LongHeaderPacketType]PacketParser{
	InitialPacketType:          ParseInitialPacket,
	RetryPacketType:            ParseRetryPacket,
	HandshakePacketType:        ParseHandshakePacket,
	ZeroRTTProtectedPacketType: ParseZeroRTTProtectedPacket,
}

type Packet interface {
	GetWire() ([]byte, error)
	SetHeader(ph PacketHeader)
}

func ParsePacket(data []byte) (packet Packet, idx int, err error) {
	version := binary.BigEndian.Uint32(data[1:5])
	if version == 0 {
		return ParseVersionNegotiationPacket(data)
	}
	header, idx, err := PacketHeaderParserMap[PacketHeaderType(data[0]&0x80)](data) // ParseHeader
	if err != nil {
		return nil, 0, err
	}
	lh, ok := header.(LongHeader)
	var idxTmp int
	if ok {
		// long header
		packet, idxTmp, err = LongHeaderPacketParserMap[LongHeaderPacketType(lh.PacketType&0x7f)](data)
	} else {
		// short header
		packet, idxTmp, err = ParseOneRTTProtectedPacket(data)
	}
	packet.SetHeader(header)
	return packet, idx + idxTmp, err
}

type BasePacket struct {
	Header PacketHeader
}

func (bp *BasePacket) SetHeader(h PacketHeader) {
	bp.Header = h
}

// long header with type of 0x7F
type InitialPacket struct {
	*BasePacket
}

func NewInitialPacket(version uint32, destConnID, srcConnID []byte, packetNumber uint32, payload []byte) *InitialPacket {
	return &InitialPacket{
		BasePacket: &BasePacket{
			Header: NewLongHeader(InitialPacketType, version, destConnID, srcConnID, packetNumber, payload),
		},
	}

}

func ParseInitialPacket(data []byte) (p Packet, length int, err error) {
	return
}

// long header with type of 0x7E
type RetryPacket struct {
	*BasePacket
}

func NewRetryPacket(version uint32, destConnID, srcConnID []byte, packetNumber uint32, payload []byte) *RetryPacket {
	return &RetryPacket{
		BasePacket: &BasePacket{
			Header: NewLongHeader(RetryPacketType, version, destConnID, srcConnID, packetNumber, payload),
		},
	}
}

func ParseRetryPacket(data []byte) (p Packet, length int, err error) {
	return
}

// long header with type of 0x7D
type HandshakePacket struct {
	*BasePacket
}

func NewHandshakePacket(version uint32, destConnID, srcConnID []byte, packetNumber uint32, payload []byte) *HandshakePacket {
	return &HandshakePacket{
		BasePacket: &BasePacket{
			Header: NewLongHeader(HandshakePacketType, version, destConnID, srcConnID, packetNumber, payload),
		},
	}
}

func ParseHandshakePacket(data []byte) (p Packet, length int, err error) {
	return
}

// long header with 0-RTT (type:0x7C)
// short header with 1-RTT
// interface?
type ProtectedPacket interface {
	GetRTT() int
}
type ZeroRTTProtectedPacket struct {
	*BasePacket
}

func NewZeroRTTProtectedPacket(version uint32, destConnID, srcConnID []byte, packetNumber uint32, payload []byte) *ZeroRTTProtectedPacket {
	return &ZeroRTTProtectedPacket{
		BasePacket: &BasePacket{
			Header: NewLongHeader(ZeroRTTProtectedPacketType, version, destConnID, srcConnID, packetNumber, payload),
		},
	}
}

func ParseZeroRTTProtectedPacket(data []byte) (p Packet, length int, err error) {
	return
}

type OneRTTProtectedPacket struct {
	*BasePacket
}

func NewOneRTTProtectedPacket(packetType byte, destConnID []byte, packetNumber uint32, payload []byte) *OneRTTProtectedPacket {
	return &OneRTTProtectedPacket{
		BasePacket: &BasePacket{
			Header: NewShortHeader(packetType, destConnID, packetNumber, payload),
		},
	}
}

func ParseOneRTTProtectedPacket(data []byte) (p Packet, length int, err error) {
	return
}

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+
   |1|  Unused (7) |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Version (32)                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |DCIL(4)|SCIL(4)|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               Destination Connection ID (0/32..144)         ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Source Connection ID (0/32..144)            ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Supported Version 1 (32)                 ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   [Supported Version 2 (32)]                ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                  ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   [Supported Version N (32)]                ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

// Version negotiation doesn't use long header, but have similar form
type VersionNegotiationPacket struct {
	Version           uint32
	DCIL              byte
	SCIL              byte
	DestConnID        []byte // 0 or 32-144bit
	SrcConnID         []byte
	SupportedVersions []uint32
}

func NewVersionNegotiationPacket(destConnID, srcConnID []byte, supportedVersions []uint32) *VersionNegotiationPacket {
	return &VersionNegotiationPacket{
		Version:           0,
		DCIL:              byte(len(destConnID) - 3),
		SCIL:              byte(len(srcConnID) - 3),
		DestConnID:        destConnID,
		SrcConnID:         srcConnID,
		SupportedVersions: supportedVersions,
	}
}

func ParseVersionNegotiationPacket(data []byte) (Packet, int, error) {
	idx := 0
	packet := NewVersionNegotiationPacket(nil, nil, nil)
	if data[0]&0x80 != 0x80 {
		//TODO: error
	}
	idx++
	packet.Version = binary.BigEndian.Uint32(data[idx:])
	if packet.Version != 0 {
		// must be zero
		// TODO: error
	}
	idx += 4
	packet.DCIL = data[idx] >> 4
	packet.SCIL = data[idx] & 0x0f
	idx++
	if packet.DCIL != 0 {
		dcil := int(packet.DCIL + 3)
		packet.DestConnID = make([]byte, dcil)
		for i := 0; i < dcil; i++ {
			packet.DestConnID[i] = data[idx+i]
		}
		idx += dcil
	}
	if packet.SCIL != 0 {
		scil := int(packet.SCIL + 3)
		packet.SrcConnID = make([]byte, scil)
		for i := 0; i < scil; i++ {
			packet.SrcConnID[i] = data[idx+i]
		}
		idx += scil
	}
	numVersions := (len(data) - idx) / 4
	packet.SupportedVersions = make([]uint32, numVersions)
	for i := 0; i < numVersions; i++ {
		packet.SupportedVersions[i] = binary.BigEndian.Uint32(data[idx:])
		idx += 4
	}
	return packet, idx, nil
}

func (p *VersionNegotiationPacket) GetWire() (wire []byte, err error) {
	wire = make([]byte, int(6+p.DCIL+p.SCIL)+len(p.SupportedVersions)*4)
	wire[0] = 0x80
	binary.BigEndian.PutUint32(wire[1:], p.Version)
	wire[5] = (p.DCIL << 4) | p.SCIL
	idx := 5
	if p.DCIL != 0 {
		for i := 0; i < int(p.DCIL+3); i++ {
			wire[idx+i] = p.DestConnID[i]
		}
		idx += int(p.DCIL + 3)
	}
	if p.SCIL != 0 {
		for i := 0; i < int(p.SCIL+3); i++ {
			wire[idx+i] = p.SrcConnID[i]
		}
		idx += int(p.SCIL + 3)
	}

	for i, version := range p.SupportedVersions {
		binary.BigEndian.PutUint32(wire[idx+i*4:], version)
	}
	return
}

func (p *VersionNegotiationPacket) SetHeader(h PacketHeader) {
	// no op
}
