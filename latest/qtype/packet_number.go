package qtype

import (
	"encoding/binary"
	"math/rand"
)

type PacketNumber uint64

const PacketNumberIncreaseSize = 1

const (
	InitialPacketNumberMin = 0
	// 2^32-1025
	InitialPacketNumberMax = 4294966271
)

func InitialPacketNumber() PacketNumber {
	return PacketNumber(uint64(rand.Int63n(InitialPacketNumberMax-InitialPacketNumberMin)) + InitialPacketNumberMin)
}

func (pn *PacketNumber) Increase() PacketNumber {
	*pn += PacketNumberIncreaseSize
	return *pn
}

func (pn PacketNumber) Bytes() []byte {
	var wire []byte
	switch {
	case pn <= 255:
		wire = make([]byte, 1)
		wire[0] = byte(pn)
	case pn <= (1<<16)-1:
		wire = make([]byte, 2)
		binary.BigEndian.PutUint16(wire, uint16(pn))
	case pn <= (1<<32)-1:
		wire = make([]byte, 4)
		binary.BigEndian.PutUint32(wire, uint32(pn))
	}

	return wire
}

func (pn PacketNumber) Size() int {
	switch {
	case pn <= 255:
		return 1
	case pn <= (1<<16)-1:
		return 2
	case pn <= (1<<32)-1:
		return 4
	}
	panic("")
}

func (pn PacketNumber) Flag() byte {
	switch {
	case pn <= 255:
		return 0x00
	case pn <= (1<<16)-1:
		return 0x01
	case pn <= (1<<32)-1:
		return 0x02
	}
	panic("")
}
