package qtype

import (
	"math"

	"github.com/ami-GS/gQUIC/latest/utils"
)

/*
   +------+--------+-------------+-----------------------+
   | 2Bit | Length | Usable Bits | Range                 |
   +------+--------+-------------+-----------------------+
   | 00   | 1      | 6           | 0-63                  |
   |      |        |             |                       |
   | 01   | 2      | 14          | 0-16383               |
   |      |        |             |                       |
   | 10   | 4      | 30          | 0-1073741823          |
   |      |        |             |                       |
   | 11   | 8      | 62          | 0-4611686018427387903 |
   +------+--------+-------------+-----------------------+
*/

type QuicInt uint64

const MaxQuicInt = 4611686018427387903

func (v QuicInt) GetEncoded() uint64 {
	switch {
	case 0 <= v && v <= 63:
		return uint64(v)
	case 0 <= v && v <= 16383:
		return uint64(v) | 0x4000
	case 0 <= v && v <= 1073741823:
		return uint64(v) | 0x80000000
	case 0 <= v && v <= MaxQuicInt:
		return uint64(v) | 0xC000000000000000
	default:
		// error
		return 0
	}
	panic("")
}

func (v QuicInt) GetFlag() byte {
	switch {
	case 0 <= v && v <= 63:
		return 0x00
	case 0 <= v && v <= 16383:
		return 0x01
	case 0 <= v && v <= 1073741823:
		return 0x02
	case 0 <= v && v <= 4611686018427387903:
		return 0x03
	default:
		// error
		return 255
	}
}

func (v QuicInt) GetByteLen() int {
	switch {
	case 0 <= v && v <= 63:
		return 1
	case 0 <= v && v <= 16383:
		return 2
	case 0 <= v && v <= 1073741823:
		return 4
	case 0 <= v && v <= 4611686018427387903:
		return 8
	default:
		// error
		return 0
	}
}

func (v QuicInt) PutWire(wire []byte) int {
	byteLen := v.GetByteLen()
	utils.MyPutUint64(wire, uint64(v.GetEncoded()), byteLen)
	return byteLen
}

func DecodeQuicInt(data []byte) QuicInt {
	flag := (data[0] & 0xc0) >> 6
	byteLen := int(math.Pow(2, float64(flag)))
	val := QuicInt(utils.MyUint64(data, byteLen))
	switch byteLen {
	case 1:
		return val
	case 2:
		return val & 0x3fff
	case 4:
		return val & 0x3fffffff
	case 8:
		return val & 0x3fffffffffffffff
	}
	panic("")
}
