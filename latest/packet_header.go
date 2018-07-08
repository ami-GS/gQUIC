package quiclatest

import (
	"encoding/binary"
	"fmt"

	"github.com/ami-GS/gQUIC/latest/qtype"
)

type LongHeaderPacketType byte

const (
	ZeroRTTProtectedPacketType LongHeaderPacketType = iota + 0x7c
	HandshakePacketType
	RetryPacketType
	InitialPacketType
)

func (lht LongHeaderPacketType) String() string {
	return map[LongHeaderPacketType]string{
		ZeroRTTProtectedPacketType: "0 RTT Protected Packet",
		HandshakePacketType:        "Handshake Packet",
		RetryPacketType:            "Retry Packet",
		InitialPacketType:          "Initial Pakcet",
	}[lht]
}

type ShortHeaderFlagType byte

const (
	KeyPhaseFlag           ShortHeaderFlagType = 0x40
	GQUICDemultipexingFlag                     = 0x08
	//Reserved                                   = 0x04
)

type ShortHeaderPacketType byte

const (
	ShortHeaderReservedBits ShortHeaderPacketType = 0x30
	KeyPhase                ShortHeaderPacketType = 0x40
)

func (sht ShortHeaderPacketType) String() string {
	keyPhase := sht&KeyPhase == KeyPhase
	return fmt.Sprintf("KeyPhrase:%v", keyPhase)
}

type PacketHeaderType byte

const (
	LongHeaderType  PacketHeaderType = 0x80
	ShortHeaderType PacketHeaderType = 0x00
)

type PacketHeader interface {
	// TODO: can be defined as different interface, like WireObject?
	GetWire() []byte
	GetWireSize() int
	genWire() ([]byte, error)
	String() string
	GetConnectionIDPair() (qtype.ConnectionID, qtype.ConnectionID) // srcID, destID
	getPacketNumber() qtype.PacketNumber
}

type BasePacketHeader struct {
	DestConnID   qtype.ConnectionID
	SrcConnID    qtype.ConnectionID
	PacketNumber qtype.PacketNumber
	wire         []byte
}

func (ph *BasePacketHeader) GetConnectionIDPair() (qtype.ConnectionID, qtype.ConnectionID) {
	return ph.SrcConnID, ph.DestConnID
}

func (ph *BasePacketHeader) getPacketNumber() qtype.PacketNumber {
	return ph.PacketNumber
}

func (ph *BasePacketHeader) GetWire() []byte {
	return ph.wire
}

func (ph *BasePacketHeader) GetWireSize() int {
	return len(ph.wire)
}

func (ph *BasePacketHeader) String() string {
	return fmt.Sprintf("DstConnID:%v\nSrcConnID:%v\nPacketNum:%d", ph.DestConnID.Bytes(), ph.SrcConnID.Bytes(), ph.PacketNumber)
}

// before passing data, need to check whether data[1:5] == 0x00 or not
// data[1:5] == 0x00 means version negotiation packet
type PacketHeaderPerser func(data []byte) (p PacketHeader, length int, err error)

var PacketHeaderParserMap = map[PacketHeaderType]PacketHeaderPerser{
	LongHeaderType:  ParseLongHeader,
	ShortHeaderType: ParseShortHeader,
}

// Long Header
/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+
   |1|   Type (7)  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Version (32)                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |DCIL(4)|SCIL(4)|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               Destination Connection ID (0/32..144)         ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Source Connection ID (0/32..144)            ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           Length (i)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Packet Number (8/16/32)                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Payload (*)                        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type LongHeader struct {
	*BasePacketHeader
	PacketType LongHeaderPacketType
	Version    qtype.Version
	DCIL       byte
	SCIL       byte
	Length     qtype.QuicInt
}

func NewLongHeader(packetType LongHeaderPacketType, version qtype.Version, destConnID, srcConnID qtype.ConnectionID, packetNumber qtype.PacketNumber, length qtype.QuicInt) *LongHeader {
	dcil := 0
	if destConnID != nil {
		dcil = len(destConnID) - 3
	}
	scil := 0
	if srcConnID != nil {
		scil = len(srcConnID) - 3
	}

	lh := &LongHeader{
		BasePacketHeader: &BasePacketHeader{
			DestConnID:   destConnID,
			SrcConnID:    srcConnID,
			PacketNumber: packetNumber,
		},
		PacketType: packetType,
		Version:    version,
		DCIL:       byte(dcil),
		SCIL:       byte(scil),
		Length:     length,
	}
	var err error
	lh.wire, err = lh.genWire()
	if err != nil {
		// error
		return nil
	}
	return lh
}

func ParseLongHeader(data []byte) (PacketHeader, int, error) {
	var err error
	idx := 0
	lh := NewLongHeader(0, 0, nil, nil, 0, 0)
	lh.PacketType = LongHeaderPacketType(data[idx] & 0x7f)
	idx++
	lh.Version = qtype.Version(binary.BigEndian.Uint32(data[idx:]))
	idx += 4
	lh.DCIL = data[idx] >> 4
	lh.SCIL = data[idx] & 0x0f
	idx++
	if lh.DCIL != 0 {
		dcil := int(lh.DCIL + 3)
		lh.DestConnID, err = qtype.ReadConnectionID(data[idx:], dcil)
		if err != nil {
			return nil, 0, err
		}
		idx += dcil
	}
	if lh.SCIL != 0 {
		scil := int(lh.SCIL + 3)
		lh.SrcConnID, err = qtype.ReadConnectionID(data[idx:], scil)
		if err != nil {
			return nil, 0, err
		}
		idx += scil
	}
	lh.Length = qtype.DecodeQuicInt(data[idx:])
	idx += lh.Length.GetByteLen()
	lh.PacketNumber = qtype.DecodePacketNumber(data[idx:])
	idx += lh.PacketNumber.GetByteLen()
	lh.wire = data[:idx]
	return lh, idx, nil
}

func (lh LongHeader) String() string {
	return fmt.Sprintf("LongHeader:%s\tVer:%s\nDCIL:%d,SCIL:%d\n%s\nLength:%d", lh.PacketType, lh.Version, lh.DCIL, lh.SCIL, lh.BasePacketHeader, lh.Length)
}

func (lh LongHeader) genWire() (wire []byte, err error) {
	wireLen := int(6 + lh.Length.GetByteLen() + lh.PacketNumber.GetByteLen())
	if lh.DCIL != 0 {
		wireLen += int(lh.DCIL + 3)
	}
	if lh.SCIL != 0 {
		wireLen += int(lh.SCIL + 3)
	}
	wire = make([]byte, wireLen)
	wire[0] = 0x80 | byte(lh.PacketType)
	binary.BigEndian.PutUint32(wire[1:], uint32(lh.Version))
	wire[5] = (lh.DCIL << 4) | lh.SCIL
	idx := 6
	if lh.DCIL != 0 {
		copy(wire[idx:], lh.DestConnID.Bytes())
		idx += int(lh.DCIL + 3)
	}
	if lh.SCIL != 0 {
		copy(wire[idx:], lh.SrcConnID.Bytes())
		idx += int(lh.SCIL + 3)
	}
	lh.Length.PutWire(wire[idx:])
	idx += lh.Length.GetByteLen()
	lh.PacketNumber.PutWire(wire[idx:])
	return
}

// Short Header
/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+
   |0|K|1|1|0|R R R|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                Destination Connection ID (0..144)           ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Packet Number (8/16/32)                ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Protected Payload (*)                   ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type ShortHeader struct {
	*BasePacketHeader
	PacketType ShortHeaderPacketType
}

func NewShortHeader(key bool, destConnID qtype.ConnectionID, packetNumber qtype.PacketNumber) *ShortHeader {
	packetType := ShortHeaderPacketType(ShortHeaderType) | 0x30

	if key {
		packetType |= KeyPhase
	}

	sh := &ShortHeader{
		BasePacketHeader: &BasePacketHeader{
			DestConnID:   destConnID,
			SrcConnID:    nil,
			PacketNumber: packetNumber,
		},
		PacketType: packetType,
	}
	var err error
	sh.wire, err = sh.genWire()
	if err != nil {
		// error
	}
	return sh
}

func ParseShortHeader(data []byte) (PacketHeader, int, error) {
	var err error
	idx := 0
	sh := NewShortHeader(false, nil, 0)
	sh.PacketType = ShortHeaderPacketType(data[idx])
	idx++
	sh.DestConnID, err = qtype.ReadConnectionID(data[idx:], qtype.ConnectionIDLen)
	if err != nil {
		return nil, 0, err
	}
	idx += qtype.ConnectionIDLen
	sh.PacketNumber = qtype.DecodePacketNumber(data[idx:])
	idx += sh.PacketNumber.GetByteLen()
	sh.wire = data[:idx]
	return sh, idx, nil
}

func (sh ShortHeader) String() string {
	return fmt.Sprintf("ShortHeader:%s\n%s", sh.PacketType, sh.BasePacketHeader)
}

func (sh ShortHeader) genWire() (wire []byte, err error) {
	connIDLen := len(sh.DestConnID)
	wire = make([]byte, 1+connIDLen+sh.PacketNumber.GetByteLen())
	wire[0] = byte(sh.PacketType)
	idx := 1
	if connIDLen != 0 {
		copy(wire[idx:idx+connIDLen], sh.DestConnID)
		idx += connIDLen
	}
	sh.PacketNumber.PutWire(wire[idx:])
	return
}
