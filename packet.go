package quic

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	qerror "github.com/ami-GS/gQUIC/error"
	"github.com/ami-GS/gQUIC/qtype"
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
	IsProbePacket() bool
}

func ParsePackets(data []byte) (packets []Packet, idx int, err error) {
	var packet Packet
	var idxTmp int
	for {
		version := binary.BigEndian.Uint32(data[idx+1 : idx+5])
		if version == 0 {
			packet, idxTmp, err = ParseVersionNegotiationPacket(data)
		} else {
			var header PacketHeader
			header, idxTmp, err = PacketHeaderParserMap[PacketHeaderType(data[idx]&0x80)](data) // ParseHeader
			if err != nil {
				return nil, 0, err
			}
			idx += idxTmp

			if lh, ok := header.(*LongHeader); ok {
				if lh.PacketType == RetryPacketType {
					packet, idxTmp, err = ParseRetryPacket(lh, data[idx:])
				} else if lh.PacketType == InitialPacketType {
					packet, idxTmp, err = ParseInitialPacket(lh, data[idx:])
					idx += idxTmp
					fs, idxTmp, err := ParseFrames(data[idx:])
					if err != nil {
						return nil, 0, err
					}
					packet.SetFrames(fs)
					if initialPacket, ok := packet.(*InitialPacket); ok {
						length := lh.getPacketNumber().GetByteLen()
						for _, frame := range fs {
							length += frame.GetWireSize()
						}

						initialPacket.PaddingNum = InitialPacketMinimumPayloadSize - length
					}
					idx += idxTmp
				} else {
					packet, idxTmp, err = newPacket(header, data[idx:idx+int(lh.Length)-lh.PacketNumber.GetByteLen()])
					if err != nil {
						return nil, 0, err
					}

					packet.SetWire(data[idx : idx+int(lh.Length)-lh.PacketNumber.GetByteLen()])
					if lh.PacketType == InitialPacketType {
					}
				}
			} else { // ShortHeader
				packet, idxTmp, err = newPacket(header, data[idx:])
				if err != nil {
					return nil, 0, err
				}
				packet.SetWire(data[idx:])
			}
		}
		idx += idxTmp
		if idx >= len(data) {
			break
		}
		packets = append(packets, packet)
	}
	if len(packets) > 1 {
		return NewCoalescingPacket(packets...), idx, err
	}
	return []Packet{packet}, idx, err

}

type BasePacket struct {
	Header     PacketHeader
	Frames     []Frame
	PaddingNum int
	payload    []byte
	isProbing  bool
}

func (bp *BasePacket) GetHeader() PacketHeader {
	return bp.Header
}
func (bp *BasePacket) SetHeader(h PacketHeader) {
	bp.Header = h
}

func (bp *BasePacket) SetFrames(fs []Frame) {
	bp.isProbing = true
	for _, f := range fs {
		if !f.IsProbeFrame() {
			bp.isProbing = false
			break
		}
	}
	bp.Frames = fs
}

func (bp *BasePacket) IsProbePacket() bool {
	return bp.isProbing
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
			return nil, 0, qerror.ProtocolViolation
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

	return p, idx + idxTmp, nil
}

/*
   +-+-+-+-+-+-+-+-+
   |1|    0x7f     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Version (32)                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |DCIL(4)|SCIL(4)|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               Destination Connection ID (0/32..144)         ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Source Connection ID (0/32..144)            ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Token Length (i)                    ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            Token (*)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           Length (i)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Packet Number (8/16/32)                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Payload (*)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

// long header with type of 0x7F
type InitialPacket struct {
	*BasePacket
	// Additional Header fields
	TokenLen qtype.QuicInt
	Token    []byte
}

const InitialPacketMinimumPayloadSize = 1200

func ParseInitialPacket(lh *LongHeader, data []byte) (*InitialPacket, int, error) {
	initialPacket := &InitialPacket{
		BasePacket: &BasePacket{
			Header: lh,
		},
	}
	initialPacket.TokenLen = qtype.DecodeQuicInt(data)
	idx := initialPacket.TokenLen.GetByteLen()
	initialPacket.Token = data[idx : idx+int(initialPacket.TokenLen)]
	idx += int(initialPacket.TokenLen)

	lh.Length = qtype.DecodeQuicInt(data[idx:])
	idx += lh.Length.GetByteLen()
	lh.PacketNumber = qtype.DecodePacketNumber(data[idx:])
	idx += lh.PacketNumber.GetByteLen()
	lh.wire = data[:idx]

	initialPacket.payload = data[idx:]
	return initialPacket, idx, nil
}

// TODO: may contain AckFrame
func NewInitialPacket(version qtype.Version, destConnID, srcConnID qtype.ConnectionID, token []byte, packetNumber qtype.PacketNumber, frames ...Frame) *InitialPacket {
	hasCrypto := false
	hasAck := false
	frameLen := 0
	for _, frame := range frames {
		if frame.GetType()|AckFrameTypeMask == AckFrameTypeA {
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
	tknLen := 0
	if token != nil {
		tknLen = len(token)
	}
	length := frameLen + packetNumber.GetByteLen()
	paddingNum := 0
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
	hWire := ip.Header.GetWire()
	additionalhWire := make([]byte, ip.TokenLen.GetByteLen())
	if ip.TokenLen >= 0 {
		_ = ip.TokenLen.PutWire(additionalhWire)
		hWire = append(hWire, append(additionalhWire, ip.Token...)...)
	}

	// here is long-header's part
	lh := ip.Header.(*LongHeader)
	longHeaderAdditionalWire := make([]byte, lh.Length.GetByteLen()+lh.PacketNumber.GetByteLen())

	lh.Length.PutWire(longHeaderAdditionalWire)
	idx := lh.Length.GetByteLen()
	lh.PacketNumber.PutWire(longHeaderAdditionalWire[idx:])

	if ip.payload != nil {
		return append(append(hWire, longHeaderAdditionalWire...), ip.payload...), nil
	}

	ip.payload, err = GetFrameWires(ip.Frames)
	if err != nil {
		return nil, err
	}
	if ip.PaddingNum != 0 {
		ip.payload = append(ip.payload, make([]byte, ip.PaddingNum)...)
	}
	// TODO: protect for short header?
	return append(append(hWire, longHeaderAdditionalWire...), ip.payload...), nil
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+
   |1|    0x7e     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Version (32)                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |DCIL(4)|SCIL(4)|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               Destination Connection ID (0/32..144)         ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Source Connection ID (0/32..144)            ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    ODCIL(8)   |      Original Destination Connection ID (*)   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Retry Token (*)                      ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

// long header with type of 0x7E
type RetryPacket struct {
	*BasePacket
	ODCIL              byte
	OriginalDestConnID qtype.ConnectionID
	RetryToken         []byte
}

func NewRetryPacket(version qtype.Version, destConnID, srcConnID qtype.ConnectionID, originalDestConnID qtype.ConnectionID, retryToken []byte) *RetryPacket {
	return &RetryPacket{
		BasePacket: &BasePacket{
			Header: NewLongHeader(RetryPacketType, version, destConnID, srcConnID, 0, qtype.QuicInt(0)),
			Frames: nil,
		},
		ODCIL:              byte(len(originalDestConnID)),
		OriginalDestConnID: originalDestConnID,
		RetryToken:         retryToken,
	}
}

func ParseRetryPacket(header *LongHeader, data []byte) (Packet, int, error) {
	p := &RetryPacket{
		BasePacket: &BasePacket{
			Header: header,
			Frames: nil,
		},
	}
	var err error
	p.ODCIL = data[0]
	p.OriginalDestConnID, err = qtype.ReadConnectionID(data[1:], int(p.ODCIL))
	if err != nil {
		return nil, 0, err
	}
	// TODO: token length?
	p.RetryToken = data[1+p.ODCIL:]
	// this is not payload strictly saying, but storing
	p.payload = data
	return p, len(data), err
}

// TODO: can be optimized
func (rp *RetryPacket) GetWire() (wire []byte, err error) {
	// TODO: PutWire([]byte) is better?
	hWire := rp.Header.GetWire()
	if rp.payload != nil {
		// bp.wire is filled after parsing
		return append(hWire, rp.payload...), nil
	}
	lh := rp.Header.(*LongHeader)
	partialLength := 6 + lh.DCIL + lh.SCIL + 6
	hWire = append(hWire[:partialLength], append([]byte{rp.ODCIL}, append(rp.OriginalDestConnID.Bytes(), rp.RetryToken...)...)...)

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

func (p RetryPacket) String() string {
	return fmt.Sprintf("%s\nODCIL:%d\nOriglDstConnID:%v\nRetryToken:[%s]", p.BasePacket, p.ODCIL, p.OriginalDestConnID.Bytes(), string(p.RetryToken))
}

// long header with type of 0x7D
type HandshakePacket struct {
	*BasePacket
}

func NewHandshakePacket(version qtype.Version, destConnID, srcConnID qtype.ConnectionID, packetNumber qtype.PacketNumber, frames ...Frame) *HandshakePacket {
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

func NewProtectedPacket1RTT(key bool, destConnID qtype.ConnectionID, packetNumber qtype.PacketNumber, frames ...Frame) *ProtectedPacket {
	return &ProtectedPacket{
		BasePacket: &BasePacket{
			Header: NewShortHeader(key, destConnID, packetNumber),
			Frames: frames,
		},
		RTT: 1,
	}
}

func NewProtectedPacket0RTT(version qtype.Version, destConnID, srcConnID qtype.ConnectionID, packetNumber qtype.PacketNumber, frames ...Frame) *ProtectedPacket {
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
		return nil, 0, qerror.ProtocolViolation
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
func (p VersionNegotiationPacket) IsProbePacket() bool {
	return false
}
func (p VersionNegotiationPacket) String() string {
	return fmt.Sprintf("NoHeader:VersionNegotiationPacket\tVer:N/A(%d)\nDCIL:%d,SCIL:%d\n%s\nSupported Versions:%v", p.Version, p.DCIL, p.SCIL, p.BasePacketHeader, p.SupportedVersions)
}

type CoalescingPacket []Packet

func NewCoalescingPacket(packets ...Packet) CoalescingPacket {
	for i, p := range packets {
		if _, ok := p.GetHeader().(*ShortHeader); ok && len(packets)-1 != i {
			panic("short header packet should be set at the end of coalescing packet")
		}
	}

	return CoalescingPacket(packets)
}

func (ps CoalescingPacket) GetWire() ([]byte, error) {
	wire, err := ps[0].GetWire()
	if err != nil {
		return nil, err
	}
	for i := 1; i < len(ps); i++ {
		p := ps[i]
		w, err := p.GetWire()
		if err != nil {
			return nil, err
		}
		wire = append(wire, w...)
	}
	return wire, nil
}

func (ps CoalescingPacket) String() string {
	out := fmt.Sprintf("%s", ps[0])
	for i := 1; i < len(ps); i++ {
		out += fmt.Sprintf("\n%s", ps[i])
	}
	return fmt.Sprintf("CoalescingPacket {\n%s}", out)
}

func (ps CoalescingPacket) SetWire(wire []byte)                 {}
func (ps CoalescingPacket) SetHeader(ph PacketHeader)           {}
func (ps CoalescingPacket) GetHeader() PacketHeader             { return nil }
func (ps CoalescingPacket) GetFrames() []Frame                  { return nil }
func (ps CoalescingPacket) GetPacketNumber() qtype.PacketNumber { return 0 }
func (ps CoalescingPacket) SetFrames(fs []Frame)                {}
func (ps CoalescingPacket) IsProbePacket() bool                 { return false }
