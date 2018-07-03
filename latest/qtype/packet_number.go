package qtype

import (
	"math"

	"github.com/ami-GS/gQUIC/latest/utils"
)

type PacketNumber uint32

const InitialPacketNumber PacketNumber = 0

const PacketNumberIncreaseSize = 1

// TODO: will be deprecated
const (
	InitialPacketNumberMin = 0
	// 2^32-1025
	InitialPacketNumberMax = 4294966271
)

func (pn PacketNumber) GetEncoded() uint32 {
	switch {
	case 0 <= pn && pn <= 127:
		return uint32(pn)
	case 0 <= pn && pn <= 16383:
		return uint32(pn) | 0x8000
	case 0 <= pn && pn <= 1073741823:
		return uint32(pn) | 0xC0000000
	default:
		return 0
	}
	panic("")
}

func (pn PacketNumber) GetByteLen() int {
	switch {
	case 0 <= pn && pn <= 127:
		return 1
	case 0 <= pn && pn <= 16383:
		return 2
	case 0 <= pn && pn <= 1073741823:
		return 4
	default:
		return 0
	}
	panic("")
}

func (pn PacketNumber) PutWire(wire []byte) int {
	byteLen := pn.GetByteLen()
	utils.MyPutUint32(wire, uint32(pn.GetEncoded()), byteLen)
	return byteLen
}

func DecodePacketNumber(data []byte) PacketNumber {
	flag := byte(0)
	if data[0]>>7 != 0 {
		flag = (data[0] & 0xc0) >> 6
	}
	byteLen := int(math.Pow(2, float64(flag)))
	val := PacketNumber(utils.MyUint32(data, byteLen))
	switch byteLen {
	case 1:
		return val
	case 2:
		return val & 0x3fff
	case 4:
		return val & 0x3fffffff
	}
	panic("")
}

func (pn *PacketNumber) Increase() PacketNumber {
	*pn += PacketNumberIncreaseSize
	return *pn
}
