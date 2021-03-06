package qtype

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestQuicInt(t *testing.T) {
	Convey("if val = 0-63, then length should be 1", t, func() {
		testset := []uint64{0, 1, 63, 63 / 2}
		for _, dat := range testset {
			qint := QuicInt(dat)
			So(qint.GetFlag(), ShouldEqual, 0x00)
			So(qint.GetByteLen(), ShouldEqual, 1)
		}
	})

	Convey("if val = 64-16383, then length should be 1", t, func() {
		testset := []uint64{64, 16383, (16383 - 64) / 2}
		for _, dat := range testset {
			qint := QuicInt(dat)
			So(qint.GetFlag(), ShouldEqual, 0x01)
			So(qint.GetByteLen(), ShouldEqual, 2)
		}
	})

	Convey("if val = 16384-1073741823, then length should be 1", t, func() {
		testset := []uint64{16384, 1073741823, (1073741823 - 16384) / 2}
		for _, dat := range testset {
			qint := QuicInt(dat)
			So(qint.GetFlag(), ShouldEqual, 0x02)
			So(qint.GetByteLen(), ShouldEqual, 4)
		}
	})

	Convey("if val = 1073741824-4611686018427387903, then length should be 1", t, func() {
		testset := []uint64{1073741824, 4611686018427387903, (4611686018427387903 - 1073741824) / 2}
		for _, dat := range testset {
			qint := QuicInt(dat)
			So(qint.GetFlag(), ShouldEqual, 0x03)
			So(qint.GetByteLen(), ShouldEqual, 8)
		}
	})
}

func TestDecodeQuicInt(t *testing.T) {
	Convey("ParseQuicInt", t, func() {
		testset := [4][][]byte{
			[][]byte{[]byte{0x00}, []byte{0x01}, []byte{31}, []byte{62}, []byte{63}},
			[][]byte{[]byte{0x40, 0x40}, []byte{0x40, 0x41}, []byte{0x7f, 0xff}, []byte{0x7f, 0xfe}, []byte{0x7f, 0xbf}},
			[][]byte{[]byte{0x80, 0x00, 0x40, 0x00}, []byte{0x80, 0x00, 0x40, 0x01}, []byte{0xbf, 0xff, 0xff, 0xff},
				[]byte{0xbf, 0xff, 0xff, 0xfe}, []byte{0x9f, 0xff, 0xdf, 0xff}},
			[][]byte{[]byte{0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00}, []byte{0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x01},
				[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe},
				[]byte{0xdf, 0xff, 0xff, 0xff, 0xdf, 0xff, 0xff, 0xff}},
		}
		valset := [4][]uint64{
			[]uint64{0, 1, 31, 62, 63},
			[]uint64{64, 65, 16383, 16382, 16319},
			[]uint64{16384, 16385, 1073741823, 1073741822, (1073741823 - 16384) / 2},
			[]uint64{1073741824, 1073741825, 4611686018427387903, 4611686018427387902, (4611686018427387903 - 1073741824) / 2},
		}
		for i, data := range testset {
			for j, dat := range data {
				qint := DecodeQuicInt(dat)
				So(uint64(qint), ShouldEqual, valset[i][j])
				So(qint.GetByteLen(), ShouldEqual, len(dat))
				So(qint.GetFlag(), ShouldEqual, dat[0]&0xc0>>6)
			}
		}
	})
}
