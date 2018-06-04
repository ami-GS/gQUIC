package quiclatest

import (
	"encoding/binary"
	"math"

	"github.com/ami-GS/gQUIC/latest/qtype"
	"github.com/ami-GS/gQUIC/utils"
)

type LongHeaderPacketType byte

const (
	InitialPacketType          LongHeaderPacketType = 0x7f
	RetryPacketType                                 = 0x7e
	HandshakePacketType                             = 0x7d
	ZeroRTTProtectedPacketType                      = 0x7c
)

type ShortHeaderFlagType byte

const (
	KeyPhaseFlag           ShortHeaderFlagType = 0x40
	GQUICDemultipexingFlag                     = 0x08
	//Reserved                                   = 0x04
)

type ShortHeaderPacketType byte

const (
	OneOctetType              ShortHeaderPacketType = 0x00
	TwoOctetsType                                   = 0x01
	FourOctetsType                                  = 0x02
	ShortHeaderPacketTypeMask                       = 0x03
)

type PacketHeaderType byte

const (
	LongHeaderType  PacketHeaderType = 0x80
	ShortHeaderType PacketHeaderType = 0x30
)

type PacketHeader interface {
	// TODO: can be defined as different interface, like WireObject?
	GetWire() []byte
	GetWireSize() int
	genWire() ([]byte, error)

	GetConnectionIDPair() (qtype.ConnectionID, qtype.ConnectionID) // srcID, destID
	GetPacketNumber() qtype.PacketNumber
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

func (ph *BasePacketHeader) GetPacketNumber() qtype.PacketNumber {
	return ph.PacketNumber
}

func (ph *BasePacketHeader) GetWire() []byte {
	return ph.wire
}

func (ph *BasePacketHeader) GetWireSize() int {
	return len(ph.wire)
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
   |                       Payload Length (i)                    ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Packet Number (32)                      |
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
	PayloadLen qtype.QuicInt
}

func NewLongHeader(packetType LongHeaderPacketType, version qtype.Version, destConnID, srcConnID qtype.ConnectionID, packetNumber qtype.PacketNumber, payloadlen uint64) *LongHeader {
	paylen, err := qtype.NewQuicInt(payloadlen)
	if err != nil {
		//error
	}
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
		PayloadLen: paylen,
	}
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
	lh.PayloadLen, _ = qtype.ParseQuicInt(data[idx:])
	idx += lh.PayloadLen.ByteLen
	lh.PacketNumber = qtype.PacketNumber(binary.BigEndian.Uint32(data[idx:]))
	lh.wire = data[:idx+4]
	return lh, idx + 4, nil
}

func (lh LongHeader) genWire() (wire []byte, err error) {
	wireLen := int(10 + lh.PayloadLen.ByteLen)

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
	idx := 5
	if lh.DCIL != 0 {
		copy(wire[idx:], lh.DestConnID.Bytes())
		idx += int(lh.DCIL + 3)
	}
	if lh.SCIL != 0 {
		copy(wire[idx:], lh.SrcConnID.Bytes())
		idx += int(lh.SCIL + 3)
	}
	lh.PayloadLen.PutWire(wire[idx:])
	idx += lh.PayloadLen.ByteLen
	binary.BigEndian.PutUint32(wire[idx:], uint32(lh.PacketNumber))
	return
}

// Short Header
/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+
   |0|K|1|1|0|R|T T|
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
	packetType := ShortHeaderPacketType(ShortHeaderType) | ShortHeaderPacketType(packetNumber.Flag())
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
	sh.DestConnID, err = qtype.ReadConnectionID(data[idx:], 8)
	if err != nil {
		return nil, 0, err
	}
	idx += 8

	packetNumLen := int(math.Pow(2, float64(sh.PacketType&ShortHeaderPacketTypeMask)))
	if packetNumLen == 8 {
		// TODO: error
		return nil, 0, nil
	}
	sh.PacketNumber = qtype.PacketNumber(utils.MyUint64(data[idx:], packetNumLen))
	idx += packetNumLen
	sh.wire = data[:idx]
	return sh, idx, nil
}

func (sh ShortHeader) genWire() (wire []byte, err error) {
	packetNumLen := int(math.Pow(2, float64(sh.PacketType&ShortHeaderPacketTypeMask)))
	connIDLen := len(sh.DestConnID)
	wire = make([]byte, 1+connIDLen+packetNumLen)
	wire[0] = byte(sh.PacketType)
	idx := 1
	if connIDLen != 0 {
		copy(wire[idx:idx+connIDLen], sh.DestConnID)
		idx += connIDLen
	}
	idx += utils.MyPutUint32(wire[idx:], uint32(sh.PacketNumber), packetNumLen)
	return
}
