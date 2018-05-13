package quiclatest

import (
	"encoding/binary"

	"github.com/ami-GS/gQUIC/latest/qtype"
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
	GetHeader() PacketHeader
	SetHeader(ph PacketHeader)
	GetFrames() []Frame
	SetFrames(fs []Frame)
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
	idx += idxTmp
	var fs []Frame
	fs, idxTmp, err = ParseFrames(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	packet.SetFrames(fs)
	return packet, idx + idxTmp, err
}

type BasePacket struct {
	Header PacketHeader
	Frames []Frame
}

func (bp *BasePacket) GetHeader() PacketHeader {
	return bp.Header
}
func (bp *BasePacket) SetHeader(h PacketHeader) {
	bp.Header = h
}

func (bp *BasePacket) SetFrames(fs []Frame) {
	bp.Frames = fs
}

func (bp *BasePacket) GetFrames() []Frame {
	return bp.Frames
}

func (bp *BasePacket) GetWire() (wire []byte, err error) {
	hWire, err := bp.Header.GetWire()
	if err != nil {
		return nil, err
	}
	fsWire, err := GetFrameWires(bp.Frames)
	if err != nil {
		return nil, err
	}
	// TODO: protect for short header?
	return append(hWire, fsWire...), nil
}

// long header with type of 0x7F
type InitialPacket struct {
	*BasePacket
}

func NewInitialPacket(version qtype.Version, destConnID, srcConnID qtype.ConnectionID, packetNumber qtype.PacketNumber, payloadLen uint64) *InitialPacket {
	return &InitialPacket{
		BasePacket: &BasePacket{
			Header: NewLongHeader(InitialPacketType, version, destConnID, srcConnID, packetNumber, payloadLen),
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

func NewRetryPacket(version qtype.Version, destConnID, srcConnID qtype.ConnectionID, packetNumber qtype.PacketNumber, payloadLen uint64) *RetryPacket {
	return &RetryPacket{
		BasePacket: &BasePacket{
			Header: NewLongHeader(RetryPacketType, version, destConnID, srcConnID, packetNumber, payloadLen),
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

func NewHandshakePacket(version qtype.Version, destConnID, srcConnID qtype.ConnectionID, packetNumber qtype.PacketNumber, payloadLen uint64) *HandshakePacket {
	return &HandshakePacket{
		BasePacket: &BasePacket{
			Header: NewLongHeader(HandshakePacketType, version, destConnID, srcConnID, packetNumber, payloadLen),
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

func NewZeroRTTProtectedPacket(version qtype.Version, destConnID, srcConnID qtype.ConnectionID, packetNumber qtype.PacketNumber, payloadLen uint64) *ZeroRTTProtectedPacket {
	return &ZeroRTTProtectedPacket{
		BasePacket: &BasePacket{
			Header: NewLongHeader(ZeroRTTProtectedPacketType, version, destConnID, srcConnID, packetNumber, payloadLen),
		},
	}
}

func ParseZeroRTTProtectedPacket(data []byte) (p Packet, length int, err error) {
	return
}

type OneRTTProtectedPacket struct {
	*BasePacket
}

func NewOneRTTProtectedPacket(packetType byte, destConnID qtype.ConnectionID, packetNumber qtype.PacketNumber) *OneRTTProtectedPacket {
	return &OneRTTProtectedPacket{
		BasePacket: &BasePacket{
			Header: NewShortHeader(packetType, destConnID, packetNumber),
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
	Version           qtype.Version
	DCIL              byte
	SCIL              byte
	DestConnID        qtype.ConnectionID
	SrcConnID         qtype.ConnectionID
	SupportedVersions []qtype.Version
}

func NewVersionNegotiationPacket(destConnID, srcConnID qtype.ConnectionID, supportedVersions []qtype.Version) *VersionNegotiationPacket {
	dcil := 0
	if destConnID != nil {
		dcil = len(destConnID) - 3
	}
	scil := 0
	if srcConnID != nil {
		scil = len(srcConnID) - 3
	}

	return &VersionNegotiationPacket{
		Version:           0,
		DCIL:              byte(dcil),
		SCIL:              byte(scil),
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
	packet.Version = qtype.Version(binary.BigEndian.Uint32(data[idx:]))
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
		qtype.ReadConnectionID(data[idx:], dcil)
		idx += dcil
	}
	if packet.SCIL != 0 {
		scil := int(packet.SCIL + 3)
		qtype.ReadConnectionID(data[idx:], scil)
		idx += scil
	}
	numVersions := (len(data) - idx) / 4
	packet.SupportedVersions = make([]qtype.Version, numVersions)
	for i := 0; i < numVersions; i++ {
		packet.SupportedVersions[i] = qtype.Version(binary.BigEndian.Uint32(data[idx:]))
		idx += 4
	}
	return packet, idx, nil
}

func (p VersionNegotiationPacket) GetWire() (wire []byte, err error) {
	wire = make([]byte, int(6+p.DCIL+p.SCIL)+len(p.SupportedVersions)*4)
	wire[0] = 0x80
	binary.BigEndian.PutUint32(wire[1:], uint32(p.Version))
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
		binary.BigEndian.PutUint32(wire[idx+i*4:], uint32(version))
	}
	// TODO: VersionNegotiationPacket fills MTU
	return
}

func (p VersionNegotiationPacket) GetHeader() PacketHeader {
	return nil
}
func (p VersionNegotiationPacket) SetHeader(h PacketHeader) {
	// no op?
}
func (p VersionNegotiationPacket) SetFrames(fs []Frame) {
	// no op?
}
func (p VersionNegotiationPacket) GetFrames() []Frame {
	return nil
}
func (p VersionNegotiationPacket) GetConnectionIDPair() (qtype.ConnectionID, qtype.ConnectionID) {
	return p.SrcConnID, p.DestConnID
}
