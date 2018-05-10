package qtype

import (
	"math/rand"
)

type PacketNumber uint64

const (
	InitialPacketNumberMin = 0
	// 2^32-1025
	InitialPacketNumberMax = 4294966271
)

func InitialPacketNumber() PacketNumber {
	return PacketNumber(uint64(rand.Int63n(InitialPacketNumberMax-InitialPacketNumberMin)) + InitialPacketNumberMin)
}
