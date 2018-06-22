package quiclatest

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/ami-GS/gQUIC/latest/qtype"
)

type Packet interface {
	// doesn't need genWire
	GetWire() ([]byte, error)
	SetWire(wire []byte)
	GetHeader() PacketHeader
	String() string
	SetHeader(ph PacketHeader)
	GetFrames() []Frame
	SetFrames(fs []Frame)
}

func ParsePacket(data []byte) (packet Packet, idx int, err error) {
	version := binary.BigEndian.Uint32(data[1:5])
	if version == 0 {
		// VersionNegotiationPacket use all UDP datagram (doesn't have frame)
		return ParseVersionNegotiationPacket(data)
	}
	header, idx, err := PacketHeaderParserMap[PacketHeaderType(data[0]&0x80)](data) // ParseHeader
	if err != nil {
		return nil, 0, err
	}
	//TODO: want to know the number of padding
	fs, idxTmp, err := ParseFrames(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	packet, err = newPacket(header, fs)
	packet.SetWire(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	return packet, idx + idxTmp, err
}

type BasePacket struct {
	Header     PacketHeader
	Frames     []Frame
	PaddingNum int
	payload    []byte
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

func (bp *BasePacket) String() string {
	frameStr := ""
	for _, frame := range bp.Frames {
		frameStr += fmt.Sprintf("\n\t%s", frame)
	}
	return fmt.Sprintf("%s\nPaddingLen:%d\n\t{%s\n\t}", bp.Header.String(), bp.PaddingNum, frameStr)
}

func (bp *BasePacket) SetWire(wire []byte) {
	bp.payload = wire
}

func (bp *BasePacket) GetPayloadLen() int {
	if bp.payload != nil {
		return len(bp.payload)
	}

	length := 0
	for _, frame := range bp.Frames {
		length += frame.GetWireSize()
	}
	return length
}

//GetWire of BasePacket assembles all wires, from header wire to frame wires
func (bp *BasePacket) GetWire() (wire []byte, err error) {
	if bp.payload != nil {
		// bp.wire is filled after parsing
		return append(bp.Header.GetWire(), bp.payload...), nil
	}
	hWire := bp.Header.GetWire()
	if err != nil {
		return nil, err
	}
	bp.payload, err = GetFrameWires(bp.Frames)
	if err != nil {
		return nil, err
	}
	if bp.PaddingNum != 0 {
		bp.payload = append(bp.payload, make([]byte, bp.PaddingNum)...)
	}
	// TODO: protect for short header?
	return append(hWire, bp.payload...), nil
}

func newPacket(ph PacketHeader, fs []Frame) (Packet, error) {
	// TODO: needs frame type validation for each packet type
	if lh, ok := ph.(*LongHeader); ok {
		payloadLen := 0
		for _, frame := range fs {
			payloadLen += frame.GetWireSize()
		}

		switch lh.PacketType {
		case InitialPacketType:
			// TODO: check whether it is stream frame or not
			return &InitialPacket{
				BasePacket: &BasePacket{
					Header:     ph,
					Frames:     fs,
					PaddingNum: InitialPacketMinimumPayloadSize - payloadLen,
				},
			}, nil
		case RetryPacketType:
			return &RetryPacket{
				&BasePacket{
					Header: ph,
					Frames: fs,
				},
			}, nil
		case HandshakePacketType:
			return &HandshakePacket{
				&BasePacket{
					Header: ph,
					Frames: fs,
				},
			}, nil
		case ZeroRTTProtectedPacketType:
			return &ProtectedPacket{
				BasePacket: &BasePacket{
					Header: ph,
					Frames: fs,
				},
				RTT: 0,
			}, nil
		default:
			// error type is not defined
			return nil, qtype.ProtocolViolation
		}
	} else if _, ok := ph.(*ShortHeader); ok {
		return &ProtectedPacket{
			BasePacket: &BasePacket{
				Header: ph,
				Frames: fs,
			},
			RTT: 1,
		}, nil
	}
	// error type is not defined
	return nil, qtype.ProtocolViolation
}

// long header with type of 0x7F
type InitialPacket struct {
	*BasePacket
}

const InitialPacketMinimumPayloadSize = 1200

func NewInitialPacket(version qtype.Version, destConnID, srcConnID qtype.ConnectionID, packetNumber qtype.PacketNumber, sFrame *StreamFrame) *InitialPacket {
	sFrameLen := sFrame.GetWireSize()
	var frames []Frame
	var lh *LongHeader
	paddingNum := 0
	if InitialPacketMinimumPayloadSize <= sFrameLen {
		// TODO: need to check when sFrameLen is over MTUIPv4
		lh = NewLongHeader(InitialPacketType, version, destConnID, srcConnID, packetNumber, qtype.QuicInt(sFrameLen))
		frames = []Frame{sFrame}
	} else {
		lh = NewLongHeader(InitialPacketType, version, destConnID, srcConnID, packetNumber, InitialPacketMinimumPayloadSize)
		frames = []Frame{sFrame}
		paddingNum = InitialPacketMinimumPayloadSize - sFrameLen
	}
	p := &InitialPacket{
		BasePacket: &BasePacket{
			Header:     lh,
			Frames:     frames,
			PaddingNum: paddingNum,
		},
	}
	return p
}

// long header with type of 0x7E
type RetryPacket struct {
	*BasePacket
}

func NewRetryPacket(version qtype.Version, destConnID, srcConnID qtype.ConnectionID, packetNumber qtype.PacketNumber, frames []Frame) *RetryPacket {
	if len(frames) < 2 {
		return nil
	}
	if _, ok := frames[0].(*StreamFrame); !ok {
		return nil
	}
	if _, ok := frames[1].(*AckFrame); !ok {
		return nil
	}
	for i := 2; i < len(frames); i++ {
		if _, ok := frames[i].(*PaddingFrame); !ok {
			return nil
		}
	}

	payloadLen := 0
	for i := 0; i < len(frames); i++ {
		payloadLen += frames[i].GetWireSize()
	}

	return &RetryPacket{
		BasePacket: &BasePacket{
			Header: NewLongHeader(RetryPacketType, version, destConnID, srcConnID, packetNumber, qtype.QuicInt(payloadLen)),
			Frames: frames,
		},
	}
}

// long header with type of 0x7D
type HandshakePacket struct {
	*BasePacket
}

func NewHandshakePacket(version qtype.Version, destConnID, srcConnID qtype.ConnectionID, packetNumber qtype.PacketNumber, frames []Frame) *HandshakePacket {
	minimumReq := false
	payloadLen := 0
	for i := 0; i < len(frames); i++ {
		switch frames[i].(type) {
		case *StreamFrame:
			minimumReq = true
			payloadLen += frames[i].GetWireSize()
		case *AckFrame, *PathChallengeFrame /*or*/, *PathResponseFrame, *ConnectionCloseFrame:
			payloadLen += frames[i].GetWireSize()
		default:
			return nil
		}
	}
	if !minimumReq {
		return nil
	}

	return &HandshakePacket{
		BasePacket: &BasePacket{
			Header: NewLongHeader(HandshakePacketType, version, destConnID, srcConnID, packetNumber, qtype.QuicInt(payloadLen)),
			Frames: frames,
		},
	}
}

// long header with 0-RTT (type:0x7C)
// short header with 1-RTT
type ProtectedPacket struct {
	*BasePacket
	RTT byte
}

func NewProtectedPacket(version qtype.Version, key bool, destConnID, srcConnID qtype.ConnectionID, packetNumber qtype.PacketNumber, rtt byte, frames []Frame) *ProtectedPacket {
	var header PacketHeader
	if rtt == 0 {
		payloadLen := 0
		for _, frame := range frames {
			payloadLen += frame.GetWireSize()
		}
		header = NewLongHeader(ZeroRTTProtectedPacketType, version, destConnID, srcConnID, packetNumber, qtype.QuicInt(payloadLen))
	} else if rtt == 1 {
		header = NewShortHeader(key, destConnID, packetNumber)
	} else {
		// error
	}

	return &ProtectedPacket{
		BasePacket: &BasePacket{
			Header: header,
			Frames: frames,
		},
		RTT: rtt,
	}
}

func (p ProtectedPacket) String() string {
	return fmt.Sprintf("%s, RTT:%d", p.BasePacket, p.RTT)
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
	*BasePacketHeader
	wire              []byte
	Version           qtype.Version
	DCIL              byte
	SCIL              byte
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

	p := &VersionNegotiationPacket{
		BasePacketHeader: &BasePacketHeader{
			DestConnID:   destConnID,
			SrcConnID:    srcConnID,
			PacketNumber: 0,
		},
		Version:           0,
		DCIL:              byte(dcil),
		SCIL:              byte(scil),
		SupportedVersions: supportedVersions,
	}
	var err error
	p.wire, err = p.genWire()
	if err != nil {
		return nil
	}
	return p
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
		packet.BasePacketHeader.DestConnID, _ = qtype.ReadConnectionID(data[idx:], dcil)
		idx += dcil
	}
	if packet.SCIL != 0 {
		scil := int(packet.SCIL + 3)
		packet.BasePacketHeader.SrcConnID, _ = qtype.ReadConnectionID(data[idx:], scil)
		idx += scil
	}
	numVersions := (len(data) - idx) / 4
	packet.SupportedVersions = make([]qtype.Version, numVersions)
	for i := 0; i < numVersions; i++ {
		packet.SupportedVersions[i] = qtype.Version(binary.BigEndian.Uint32(data[idx:]))
		idx += 4
	}
	packet.wire = data
	return packet, idx, nil
}

func (p VersionNegotiationPacket) genWire() (wire []byte, err error) {
	wireLen := 6 + len(p.SupportedVersions)*4
	if p.DCIL != 0 {
		wireLen += int(p.DCIL + 3)
	}
	if p.SCIL != 0 {
		wireLen += int(p.SCIL + 3)
	}
	//wireLen = qtype.MTUIPv4
	wire = make([]byte, wireLen)
	if _, err := rand.Read(wire[0:1]); err != nil {
		return nil, err
	}
	wire[0] |= 0x80
	binary.BigEndian.PutUint32(wire[1:], uint32(p.Version))
	wire[5] = (p.DCIL << 4) | p.SCIL
	idx := 6
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

func (p VersionNegotiationPacket) SetWire(wire []byte) {
	// actual set is done in ParseVersionNegotiationPacket()
}

func (p VersionNegotiationPacket) GetWire() ([]byte, error) {
	return p.wire, nil
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
func (p VersionNegotiationPacket) String() string {
	return fmt.Sprintf("NoHeader:VersionNegotiationPacket\tVer:%d\nDCIL:%d,SCIL:%d\n%s\nSupported Versions:%v", p.Version, p.DCIL, p.SCIL, p.BasePacketHeader, p.SupportedVersions)
}
