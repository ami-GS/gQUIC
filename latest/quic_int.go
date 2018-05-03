package quiclatest

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

//GetValue() returns decoded value
type QuicInt struct {
	Value   uint64 // encoded
	Flag    byte
	ByteLen int
}

func NewQuicInt(value uint64) (*QuicInt, error) {
	val, flag, err := EncodeToValue(value)
	if err != nil {
		return nil, err
	}
	return &QuicInt{
		Value:   val,
		Flag:    flag,
		ByteLen: int(math.Pow(2, float64(flag))),
	}, nil
}

func (v *QuicInt) GetValue() uint64 {
	val := uint64(0)
	val |= v.Value & (0xcf << uint64((v.ByteLen-1)*8))
	for i := 1; i < v.ByteLen; i++ {
		val |= v.Value & (0xff << uint64((v.ByteLen-1-i)*8))
	}
	return val
}

func (v *QuicInt) PutWire(wire []byte) {
	utils.MyPutUint64(wire, v.Value, v.ByteLen)
}

func ParseQuicInt(data []byte) (*QuicInt, error) {
	flag := data[0] & 0xc0
	ret := &QuicInt{
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
	case 0 <= val && val <= 461168601842738790:
		byteFlag = 0x03
	default:
		return 0, 0, err
		// error
	}
	byteLen := int(math.Pow(2, float64(byteFlag)))
	for i := 0; i < byteLen; i++ {
		shift := uint8((byteLen - 1 - i) * 8)
		if i == 0 {
			ret |= uint64(byteFlag) | (uint64((val>>shift)&0xff) << shift)
		} else {
			ret |= uint64((val>>shift)&0xff) << shift
		}
	}
	return ret, byteFlag, nil
}

func DecodeToValue(data []byte) (ret uint64, byteLen int, err error) {
	ret = uint64(data[0] & 0x3f)
	byteFlag := data[0] >> 6
	byteLen = int(math.Pow(2, float64(byteFlag)))
	for i := 0; i < byteLen; i++ {
		shift := uint8(byteLen-1-i) * 8
		if i == 0 {
			ret |= uint64((data[i] & 0xcf)) << shift
		} else {
			ret |= uint64(data[i]) << shift
		}
	}
	return ret, byteLen, nil
}
