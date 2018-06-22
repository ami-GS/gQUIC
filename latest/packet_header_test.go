package quiclatest

import (
	"testing"

	"github.com/ami-GS/gQUIC/latest/qtype"
	. "github.com/smartystreets/goconvey/convey"
)

func TestNewLongHeader(t *testing.T) {
	var err error
	pn := qtype.InitialPacketNumber()
	Convey("If connection IDs are absent, DCIL and SCIL should be 0", t, func() {
		dstID := (qtype.ConnectionID)(nil)
		srcID := (qtype.ConnectionID)(nil)
		eHeader := &LongHeader{
			BasePacketHeader: &BasePacketHeader{
				DestConnID:   dstID,
				SrcConnID:    srcID,
				PacketNumber: pn,
			},
			PacketType: InitialPacketType,
			Version:    qtype.VersionQuicTLS,
			DCIL:       0,
			SCIL:       0,
			PayloadLen: qtype.QuicInt(0),
		}
		eHeader.wire, err = eHeader.genWire()
		aHeader := NewLongHeader(InitialPacketType, qtype.VersionQuicTLS, dstID, srcID, pn, 0)
		So(err, ShouldBeNil)
		So(aHeader, ShouldResemble, eHeader)
	})
	Convey("If random connection IDs (length of 18), DCIL and SCIL should be 15", t, func() {
		dstID, _ := qtype.NewConnectionID(nil)
		srcID, _ := qtype.NewConnectionID(nil)
		eHeader := &LongHeader{
			BasePacketHeader: &BasePacketHeader{
				DestConnID:   dstID,
				SrcConnID:    srcID,
				PacketNumber: pn,
			},
			PacketType: InitialPacketType,
			Version:    qtype.VersionQuicTLS,
			DCIL:       byte(len(dstID)) - 3,
			SCIL:       byte(len(srcID)) - 3,
			PayloadLen: qtype.QuicInt(0),
		}
		eHeader.wire, err = eHeader.genWire()
		aHeader := NewLongHeader(InitialPacketType, qtype.VersionQuicTLS, dstID, srcID, pn, 0)
		So(err, ShouldBeNil)
		So(aHeader, ShouldResemble, eHeader)
	})
}

func TestParseLongHeader(t *testing.T) {
	Convey("Parse bytes of of InitialPacketType, Version:QuicTLS, DCIL:0, SCIL:0, dstID/srcID:nil/nil, PayloadLen:0, PacketNumber:1, Payload:nil", t, func() {
		data := []byte{0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
		aHeader, aLen, err := ParseLongHeader(data)
		eHeader := NewLongHeader(InitialPacketType, qtype.VersionQuicTLS, nil, nil, 1, 0)
		So(aLen, ShouldEqual, len(data))
		So(err, ShouldBeNil)
		So(aHeader, ShouldResemble, eHeader)
	})

	Convey("Parse bytes of of InitialPacketType, Version:QuicTLS, DCIL:15, SCIL:15, dstID/srcID:rand/rand, PayloadLen:0, PacketNumber:1, Payload:nil", t, func() {
		// default length is 18
		dstID, _ := qtype.NewConnectionID(nil)
		srcID, _ := qtype.NewConnectionID(nil)
		data := []byte{0xff, 0x00, 0x00, 0x00, 0x01, 0xff}
		data = append(data, dstID.Bytes()...)
		data = append(data, srcID.Bytes()...)
		data = append(data, 0x00, 0x00, 0x00, 0x00, 0x01)
		aHeader, aLen, err := ParseLongHeader(data)
		eHeader := NewLongHeader(InitialPacketType, qtype.VersionQuicTLS, dstID, srcID, 1, 0)
		So(aLen, ShouldEqual, len(data))
		So(err, ShouldBeNil)
		So(aHeader, ShouldResemble, eHeader)
	})
}

func TestNewShortHeader(t *testing.T) {
	dstID, _ := qtype.NewConnectionID(nil)
	var err error
	Convey("ConnectionID:rand, PacketNumber:1", t, func() {
		pn := qtype.PacketNumber(1)
		aHeader := NewShortHeader(false, dstID, pn)
		eHeader := &ShortHeader{
			BasePacketHeader: &BasePacketHeader{
				DestConnID:   dstID,
				SrcConnID:    nil,
				PacketNumber: pn,
			},
			PacketType: ShortHeaderPacketType(ShortHeaderType) | ShortHeaderPacketType(pn.Flag()),
		}
		eHeader.wire, err = eHeader.genWire()
		So(err, ShouldBeNil)
		So(aHeader, ShouldResemble, eHeader)
	})
	Convey("ConnectionID:rand, PacketNumber:256", t, func() {
		pn := qtype.PacketNumber(256)
		aHeader := NewShortHeader(false, dstID, pn)
		eHeader := &ShortHeader{
			BasePacketHeader: &BasePacketHeader{
				DestConnID:   dstID,
				SrcConnID:    nil,
				PacketNumber: pn,
			},
			PacketType: ShortHeaderPacketType(ShortHeaderType) | ShortHeaderPacketType(pn.Flag()),
		}
		eHeader.wire, err = eHeader.genWire()
		So(err, ShouldBeNil)
		So(aHeader, ShouldResemble, eHeader)
	})
	Convey("ConnectionID:rand, PacketNumber:65536", t, func() {
		pn := qtype.PacketNumber(65536)
		aHeader := NewShortHeader(false, dstID, pn)
		eHeader := &ShortHeader{
			BasePacketHeader: &BasePacketHeader{
				DestConnID:   dstID,
				SrcConnID:    nil,
				PacketNumber: pn,
			},
			PacketType: ShortHeaderPacketType(ShortHeaderType) | ShortHeaderPacketType(pn.Flag()),
		}
		eHeader.wire, err = eHeader.genWire()
		So(err, ShouldBeNil)
		So(aHeader, ShouldResemble, eHeader)
	})
}

func TestParseShortHeader(t *testing.T) {
	dstID, _ := qtype.NewConnectionID(nil)
	Convey("type:0x30, ConnectionID:rand, PacketNumber:1, payload:nil", t, func() {
		pn := qtype.PacketNumber(1)
		data := []byte{0x30}
		data = append(data, dstID.Bytes()...)
		data = append(data, pn.Bytes()...)
		aHeader, length, err := ParseShortHeader(data)
		eHeader := &ShortHeader{
			BasePacketHeader: &BasePacketHeader{
				DestConnID:   dstID,
				SrcConnID:    nil,
				PacketNumber: pn,
			},
			PacketType: ShortHeaderPacketType(byte(ShortHeaderReservedBits) | pn.Flag()),
		}
		eHeader.wire, err = eHeader.genWire()
		So(err, ShouldBeNil)
		So(length, ShouldEqual, len(data))
		So(err, ShouldBeNil)
		So(aHeader, ShouldResemble, eHeader)
	})
	Convey("type:0x31, ConnectionID:rand, PacketNumber:256, payload:nil", t, func() {
		pn := qtype.PacketNumber(256)
		data := []byte{0x31}
		data = append(data, dstID.Bytes()...)
		data = append(data, pn.Bytes()...)
		aHeader, length, err := ParseShortHeader(data)
		eHeader := &ShortHeader{
			BasePacketHeader: &BasePacketHeader{
				DestConnID:   dstID,
				SrcConnID:    nil,
				PacketNumber: pn,
			},
			PacketType: ShortHeaderPacketType(byte(ShortHeaderReservedBits) | pn.Flag()),
		}
		eHeader.wire, err = eHeader.genWire()
		So(err, ShouldBeNil)
		So(length, ShouldEqual, len(data))
		So(err, ShouldBeNil)
		So(aHeader, ShouldResemble, eHeader)
	})
	Convey("type:0x32, ConnectionID:rand, PacketNumber:65536, payload:nil", t, func() {
		pn := qtype.PacketNumber(65536)
		data := []byte{0x32}
		data = append(data, dstID.Bytes()...)
		data = append(data, pn.Bytes()...)
		aHeader, length, err := ParseShortHeader(data)
		eHeader := &ShortHeader{
			BasePacketHeader: &BasePacketHeader{
				DestConnID:   dstID,
				SrcConnID:    nil,
				PacketNumber: pn,
			},
			PacketType: ShortHeaderPacketType(byte(ShortHeaderReservedBits) | pn.Flag()),
		}
		eHeader.wire, err = eHeader.genWire()
		So(err, ShouldBeNil)
		So(length, ShouldEqual, len(data))
		So(err, ShouldBeNil)
		So(aHeader, ShouldResemble, eHeader)
	})
}
