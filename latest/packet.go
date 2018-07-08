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
	GetPacketNumber() qtype.PacketNumber
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

	if lh, ok := header.(*LongHeader); ok {
		if lh.PacketType == InitialPacketType {
		} else if lh.PacketType == RetryPacketType {

		}
	}
	// TODO: not good name or return values
	packet, idxTmp, err := newPacket(header, data[idx:])
	if err != nil {
		return nil, 0, err
	}
	packet.SetWire(data[idx:])
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
func (bp *BasePacket) GetPacketNumber() qtype.PacketNumber {
	return bp.Header.getPacketNumber()
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

func newPacket(ph PacketHeader, data []byte) (p Packet, idx int, err error) {
	// TODO: needs frame type validation for each packet type
	if lh, ok := ph.(*LongHeader); ok {
		switch lh.PacketType {
		case InitialPacketType:
			// TODO: check whether it is stream frame or not
			initialPacket := &InitialPacket{
				BasePacket: &BasePacket{
					Header: ph,
				},
			}
			initialPacket.TokenLen = qtype.DecodeQuicInt(data)
			idx += initialPacket.TokenLen.GetByteLen()
			initialPacket.Token = data[idx : idx+int(initialPacket.TokenLen)]
			idx += int(initialPacket.TokenLen)
			p = Packet(initialPacket)
		case RetryPacketType:
			retryPacket := &RetryPacket{
				BasePacket: &BasePacket{
					Header: ph,
				},
			}
			retryPacket.ODCIL = data[idx]
			retryPacket.OriginalDestConnID, err = qtype.ReadConnectionID(data[idx+1:], int(retryPacket.ODCIL))
			if err != nil {
				return nil, 0, err
			}
			retryPacket.RetryToken = data[idx+1+int(retryPacket.ODCIL):]
			// TODO: check no frame is correct
			return retryPacket, idx + 1 + int(retryPacket.ODCIL) + len(data), nil
		case HandshakePacketType:
			p = &HandshakePacket{
				&BasePacket{
					Header: ph,
				},
			}
		case ZeroRTTProtectedPacketType:
			p = &ProtectedPacket{
				BasePacket: &BasePacket{
					Header: ph,
				},
				RTT: 0,
			}
		default:
			// error type is not defined
			return nil, 0, qtype.ProtocolViolation
		}
	} else if _, ok := ph.(*ShortHeader); ok {
		p = &ProtectedPacket{
			BasePacket: &BasePacket{
				Header: ph,
			},
			RTT: 1,
		}
	}

	fs, idxTmp, err := ParseFrames(data[idx:])
	if err != nil {
		return nil, 0, err
	}
	p.SetFrames(fs)
	if initialPacket, ok := p.(*InitialPacket); ok {
		length := ph.getPacketNumber().GetByteLen()
		for _, frame := range fs {
			length += frame.GetWireSize()
		}

		initialPacket.PaddingNum = InitialPacketMinimumPayloadSize - length
	}

	return p, idx + idxTmp, nil
}

// long header with type of 0x7F
type InitialPacket struct {
	*BasePacket
	// Additional Header fields
	TokenLen qtype.QuicInt
	Token    []byte
}

const InitialPacketMinimumPayloadSize = 1200

// TODO: may contain AckFrame
func NewInitialPacket(version qtype.Version, destConnID, srcConnID qtype.ConnectionID, token []byte, packetNumber qtype.PacketNumber, frames []Frame) *InitialPacket {
	hasCrypto := false
	hasAck := false
	frameLen := 0
	for _, frame := range frames {
		if frame.GetType() == AckFrameType {
			if hasAck {
				// should be single ack?
				return nil
			}
			hasAck = true
		} else if frame.GetType() == CryptoFrameType {
			if hasCrypto {
				// should be single crypto?
				return nil
			}
			hasCrypto = true
		}
		frameLen += frame.GetWireSize()
	}
	if !hasAck && !hasCrypto {
		return nil
	}
	var lh *LongHeader
	paddingNum := 0
	additionalLen := 1
	tknLen := 0
	if token != nil {
		tknLen = len(token)
		additionalLen = tknLen + qtype.QuicInt(tknLen).GetByteLen()
	}
	length := frameLen + packetNumber.GetByteLen() + additionalLen
	if InitialPacketMinimumPayloadSize <= length {
		lh = NewLongHeader(InitialPacketType, version, destConnID, srcConnID, packetNumber, qtype.QuicInt(length))
	} else {
		lh = NewLongHeader(InitialPacketType, version, destConnID, srcConnID, packetNumber, InitialPacketMinimumPayloadSize)
		paddingNum = InitialPacketMinimumPayloadSize - length
	}
	p := &InitialPacket{
		BasePacket: &BasePacket{
			Header:     lh,
			Frames:     frames,
			PaddingNum: paddingNum,
		},
		TokenLen: qtype.QuicInt(tknLen),
		Token:    token,
	}
	return p
}

// TODO: can be optimized
func (ip *InitialPacket) GetWire() (wire []byte, err error) {
	if ip.payload != nil {
		// bp.wire is filled after parsing
		return append(ip.Header.GetWire(), ip.payload...), nil
	}
	// TODO: PutWire([]byte) is better?
	hWire := ip.Header.GetWire()
	if err != nil {
		return nil, err
	}
	additionalhWire := make([]byte, ip.TokenLen.GetByteLen())
	if ip.TokenLen >= 0 {
		_ = ip.TokenLen.PutWire(additionalhWire)
		hWire = append(hWire, append(additionalhWire, ip.Token...)...)
	}

	ip.payload, err = GetFrameWires(ip.Frames)
	if err != nil {
		return nil, err
	}
	if ip.PaddingNum != 0 {
		ip.payload = append(ip.payload, make([]byte, ip.PaddingNum)...)
	}
	// TODO: protect for short header?
	return append(hWire, ip.payload...), nil
}

// long header with type of 0x7E
type RetryPacket struct {
	*BasePacket
	ODCIL              byte
	OriginalDestConnID qtype.ConnectionID
	RetryToken         []byte
}

func NewRetryPacket(version qtype.Version, destConnID, srcConnID qtype.ConnectionID, originalDestConnID qtype.ConnectionID, retryToken []byte, packetNumber qtype.PacketNumber) *RetryPacket {
	length := 1 + len(originalDestConnID) + len(retryToken) + packetNumber.GetByteLen()
	return &RetryPacket{
		BasePacket: &BasePacket{
			Header: NewLongHeader(RetryPacketType, version, destConnID, srcConnID, packetNumber, qtype.QuicInt(length)),
			Frames: nil,
		},
		ODCIL:              byte(len(originalDestConnID)),
		OriginalDestConnID: originalDestConnID,
		RetryToken:         retryToken,
	}
}

// TODO: can be optimized
func (rp *RetryPacket) GetWire() (wire []byte, err error) {
	if rp.payload != nil {
		// bp.wire is filled after parsing
		return append(rp.Header.GetWire(), rp.payload...), nil
	}
	// TODO: PutWire([]byte) is better?
	hWire := rp.Header.GetWire()
	if err != nil {
		return nil, err
	}
	hWire = append(hWire, append([]byte{rp.ODCIL}, append(rp.OriginalDestConnID.Bytes(), rp.RetryToken...)...)...)

	if rp.Frames != nil {
		rp.payload, err = GetFrameWires(rp.Frames)
		if err != nil {
			return nil, err
		}
	}
	if rp.PaddingNum != 0 {
		rp.payload = append(rp.payload, make([]byte, rp.PaddingNum)...)
	}
	// TODO: protect for short header?
	return append(hWire, rp.payload...), nil
}

// long header with type of 0x7D
type HandshakePacket struct {
	*BasePacket
}

func NewHandshakePacket(version qtype.Version, destConnID, srcConnID qtype.ConnectionID, packetNumber qtype.PacketNumber, frames []Frame) *HandshakePacket {
	minimumReq := false
	length := packetNumber.GetByteLen()
	for i := 0; i < len(frames); i++ {
		switch frames[i].(type) {
		case *ConnectionCloseFrame:
			// This stands for the handshake is unsaccessful
			minimumReq = true
		case *CryptoFrame:
			minimumReq = true
		case *AckFrame:
		default:
			// TODO: error, handshake packet cannot have these frames
			return nil
		}
		length += frames[i].GetWireSize()
	}
	if !minimumReq {
		return nil
	}

	return &HandshakePacket{
		BasePacket: &BasePacket{
			Header: NewLongHeader(HandshakePacketType, version, destConnID, srcConnID, packetNumber, qtype.QuicInt(length)),
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

func NewProtectedPacket1RTT(key bool, destConnID qtype.ConnectionID, packetNumber qtype.PacketNumber, frames []Frame) *ProtectedPacket {
	return &ProtectedPacket{
		BasePacket: &BasePacket{
			Header: NewShortHeader(key, destConnID, packetNumber),
			Frames: frames,
		},
		RTT: 1,
	}
}

func NewProtectedPacket0RTT(version qtype.Version, destConnID, srcConnID qtype.ConnectionID, packetNumber qtype.PacketNumber, frames []Frame) *ProtectedPacket {
	length := packetNumber.GetByteLen()
	for _, frame := range frames {
		length += frame.GetWireSize()
	}

	return &ProtectedPacket{
		BasePacket: &BasePacket{
			Header: NewLongHeader(ZeroRTTProtectedPacketType, version, destConnID, srcConnID, packetNumber, qtype.QuicInt(length)),
			Frames: frames,
		},
		RTT: 0,
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
		// must be zero, but the error is not defined
		return nil, 0, qtype.ProtocolViolation
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
func (p VersionNegotiationPacket) GetPacketNumber() qtype.PacketNumber {
	return 0
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
	return fmt.Sprintf("NoHeader:VersionNegotiationPacket\tVer:N/A(%d)\nDCIL:%d,SCIL:%d\n%s\nSupported Versions:%v", p.Version, p.DCIL, p.SCIL, p.BasePacketHeader, p.SupportedVersions)
}
