package qtype

import (
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
