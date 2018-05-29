package qtype

import (
	"math"

	"github.com/ami-GS/gQUIC/utils"
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

type QuicInt struct {
	Value   uint64 // encoded
	Flag    byte
	ByteLen int
}

func NewQuicInt(value uint64) (QuicInt, error) {
	val, flag, err := EncodeToValue(value)
	if err != nil {
		return QuicInt{0, 0, 0}, err
	}
	return QuicInt{
		Value:   val,
		Flag:    flag,
		ByteLen: int(math.Pow(2, float64(flag))),
	}, nil
}

func (v QuicInt) GetValue() uint64 {
	switch v.Flag {
	case 0x00:
		return v.Value
	case 0x01:
		return v.Value & 0x3fff
	case 0x02:
		return v.Value & 0x7fffffff
	case 0x03:
		return v.Value & 0x3fffffffffffffff
	}
	return 0
}

func (v QuicInt) Less(right *QuicInt) bool {
	return v.GetValue() < right.GetValue()
}

func (v QuicInt) Equal(right *QuicInt) bool {
	return v.GetValue() == right.GetValue()
}

func (v QuicInt) PutWire(wire []byte) int {
	utils.MyPutUint64(wire, v.Value, v.ByteLen)
	return v.ByteLen
}

func ParseQuicInt(data []byte) (QuicInt, error) {
	flag := (data[0] & 0xc0) >> 6
	ret := QuicInt{
		Flag:    flag,
		ByteLen: int(math.Pow(2, float64(flag))),
		Value:   0,
	}
	ret.Value = utils.MyUint64(data, ret.ByteLen)
	return ret, nil
}

func EncodeToValue(val uint64) (ret uint64, byteFlag byte, err error) {
	byteFlag = byte(0x00)
	switch {
	case 0 <= val && val <= 63:
	case 0 <= val && val <= 16383:
		byteFlag = 0x01
	case 0 <= val && val <= 1073741823:
		byteFlag = 0x02
	case 0 <= val && val <= 4611686018427387903:
		byteFlag = 0x03
	default:
		return 0, 0, err
		// error
	}
	byteLen := int(math.Pow(2, float64(byteFlag)))

	for i := 0; i < byteLen; i++ {
		shift := uint8((byteLen - 1 - i) * 8)
		if i == 0 {
			ret |= uint64((val>>shift)&0xff) << shift
			ret |= uint64(byteFlag) << byte(((byteLen * 8) - 2))
		} else {
			ret |= uint64((val>>shift)&0xff) << shift
		}
	}

	return ret, byteFlag, nil
}
