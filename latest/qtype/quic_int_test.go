package qtype

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestNewQuicInt(t *testing.T) {
	Convey("if val = 0-63, then length should be 1", t, func() {
		testset := []uint64{0, 1, 63, 63 / 2}
		for _, dat := range testset {
			qint, err := NewQuicInt(dat)
			So(err, ShouldBeNil)
			So(qint.Value, ShouldEqual, dat)
			So(qint.Flag, ShouldEqual, 0x00)
			So(qint.ByteLen, ShouldEqual, 1)
		}
	})

	Convey("if val = 64-16383, then length should be 1", t, func() {
		testset := []uint64{64, 16383, (16383 - 64) / 2}
		for _, dat := range testset {
			qint, err := NewQuicInt(dat)
			So(err, ShouldBeNil)
			So(qint.Value, ShouldEqual, dat|0x4000)
			So(qint.Flag, ShouldEqual, 0x01)
			So(qint.ByteLen, ShouldEqual, 2)
		}
	})

	Convey("if val = 16384-1073741823, then length should be 1", t, func() {
		testset := []uint64{16384, 1073741823, (1073741823 - 16384) / 2}
		for _, dat := range testset {
			qint, err := NewQuicInt(dat)
			So(err, ShouldBeNil)
			So(qint.Value, ShouldEqual, dat|0x80000000)
			So(qint.Flag, ShouldEqual, 0x02)
			So(qint.ByteLen, ShouldEqual, 4)
		}
	})

	Convey("if val = 1073741824-4611686018427387903, then length should be 1", t, func() {
		testset := []uint64{1073741824, 4611686018427387903, (4611686018427387903 - 1073741824) / 2}
		for _, dat := range testset {
			qint, err := NewQuicInt(dat)
			So(err, ShouldBeNil)
			So(qint.Value, ShouldEqual, dat|0xc000000000000000)
			So(qint.Flag, ShouldEqual, 0x03)
			So(qint.ByteLen, ShouldEqual, 8)
		}
	})
}

func TestGetValue(t *testing.T) {
	Convey("val = 0-63", t, func() {
		testset := []uint64{0, 1, 63, 63 / 2}
		for _, dat := range testset {
			qint, _ := NewQuicInt(dat)
			So(qint.GetValue(), ShouldEqual, dat)
		}
	})

	Convey("if val = 64-16383, then length should be 1", t, func() {
		testset := []uint64{64, 16383, (16383 - 64) / 2}
		for _, dat := range testset {
			qint, _ := NewQuicInt(dat)
			So(qint.GetValue(), ShouldEqual, dat)
		}
	})

	Convey("if val = 16384-1073741823, then length should be 1", t, func() {
		testset := []uint64{16384, 1073741823, (1073741823 - 16384) / 2}
		for _, dat := range testset {
			qint, _ := NewQuicInt(dat)
			So(qint.GetValue(), ShouldEqual, dat)
		}
	})

	Convey("if val = 1073741824-4611686018427387903, then length should be 1", t, func() {
		testset := []uint64{1073741824, 4611686018427387903, (4611686018427387903 - 1073741824) / 2}
		for _, dat := range testset {
			qint, _ := NewQuicInt(dat)
			So(qint.GetValue(), ShouldEqual, dat)
		}
	})
}

func TestParseQuicInt(t *testing.T) {
	Convey("ParseQuicInt", t, func() {
		testset := [4][][]byte{
			[][]byte{[]byte{0x00}, []byte{0x01}, []byte{31}, []byte{62}, []byte{63}},
			[][]byte{[]byte{0x40, 0x40}, []byte{0x40, 0x41}, []byte{0x7f, 0xff}, []byte{0x7f, 0xfe}, []byte{0x7f, 0xbf}},
		}
		valset := [4][]uint64{
			[]uint64{0, 1, 31, 62, 63},
			[]uint64{64, 65, 16383, 16382, 16319},
		}

		for i, data := range testset {
			for j, dat := range data {
				qint, err := ParseQuicInt(dat)
				So(err, ShouldBeNil)
				So(qint.GetValue(), ShouldEqual, valset[i][j])
				So(qint.ByteLen, ShouldEqual, len(dat))
				So(qint.Flag, ShouldEqual, dat[0]&0xc0>>6)
			}
		}
	})
}
