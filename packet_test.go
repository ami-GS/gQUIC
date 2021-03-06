package quic

import (
	"testing"

	"github.com/ami-GS/gQUIC/qtype"
	. "github.com/smartystreets/goconvey/convey"
)

func TestNewPacket(t *testing.T) {
	dstConnID, _ := qtype.NewConnectionID(nil)
	srcConnID, _ := qtype.NewConnectionID(nil)
	pn := qtype.PacketNumber(1)
	Convey("InitialPacketType", t, func() {
		sFrame := NewStreamFrame(0, 0, true, true, true, []byte{0x11, 0x22})
		header := NewLongHeader(InitialPacketType, qtype.VersionQuicTLS, dstConnID, srcConnID, pn, InitialPacketMinimumPayloadSize)
		ePacket := NewInitialPacket(qtype.VersionQuicTLS, dstConnID, srcConnID, pn, sFrame)
		aPacket, err := newPacket(header, []Frame{sFrame})
		So(err, ShouldBeNil)
		So(aPacket, ShouldResemble, ePacket)
	})
	Convey("RetryPacketType", t, func() {
		sFrame := NewStreamFrame(0, 0, true, true, true, []byte{0x11, 0x22})
		aFrame := NewAckFrame(2, 3, []AckBlock{AckBlock{32, 0}})
		frames := []Frame{sFrame, aFrame}
		payloadLen := 0
		for _, f := range frames {
			payloadLen += f.GetWireSize()
		}
		header := NewLongHeader(RetryPacketType, qtype.VersionQuicTLS, dstConnID, srcConnID, pn, qtype.QuicInt(payloadLen))
		ePacket := NewRetryPacket(qtype.VersionQuicTLS, dstConnID, srcConnID, pn, []Frame{sFrame, aFrame})
		aPacket, err := newPacket(header, []Frame{sFrame, aFrame})
		So(err, ShouldBeNil)
		So(aPacket, ShouldResemble, ePacket)
	})
	Convey("HandshakePacketType", t, func() {
		sFrame := NewStreamFrame(0, 0, true, true, true, []byte{0x11, 0x22})
		frames := []Frame{sFrame}
		header := NewLongHeader(HandshakePacketType, qtype.VersionQuicTLS, dstConnID, srcConnID, pn, qtype.QuicInt(frames[0].GetWireSize()))
		aPacket, err := newPacket(header, frames)
		ePacket := NewHandshakePacket(qtype.VersionQuicTLS, dstConnID, srcConnID, pn, frames)
		So(err, ShouldBeNil)
		So(aPacket, ShouldResemble, ePacket)
	})
	Convey("ZeroRTTPacketType", t, func() {
		sFrame := NewStreamFrame(0, 0, true, true, true, []byte{0x11, 0x22})
		frames := []Frame{sFrame}
		header := NewLongHeader(ZeroRTTProtectedPacketType, qtype.VersionQuicTLS, dstConnID, srcConnID, pn, qtype.QuicInt(frames[0].GetWireSize()))
		aPacket, err := newPacket(header, frames)
		ePacket := NewProtectedPacket(qtype.VersionQuicTLS, false, dstConnID, srcConnID, pn, 0, frames)
		So(err, ShouldBeNil)
		So(aPacket, ShouldResemble, ePacket)
	})
	Convey("OneRTTPacketType", t, func() {
		sFrame := NewStreamFrame(0, 0, true, true, true, []byte{0x11, 0x22})
		frames := []Frame{sFrame}
		header := NewShortHeader(false, dstConnID, pn)
		aPacket, err := newPacket(header, frames)
		ePacket := NewProtectedPacket(qtype.VersionQuicTLS, false, dstConnID, srcConnID, pn, 1, frames)
		So(err, ShouldBeNil)
		So(aPacket, ShouldResemble, ePacket)
	})
}

func TestParsePacket(t *testing.T) {
	dstConnID, _ := qtype.NewConnectionID(nil)
	srcConnID, _ := qtype.NewConnectionID(nil)
	pn := qtype.PacketNumber(1)
	Convey("InitialPacketType", t, func() {
		sFrame := NewStreamFrame(0, 0, true, true, true, []byte{0x11, 0x22})
		ePacket := NewInitialPacket(qtype.VersionQuicTLS, dstConnID, srcConnID, pn, sFrame)
		wire, err := ePacket.GetWire()
		So(err, ShouldBeNil)
		aPacket, length, err := ParsePacket(wire)
		So(err, ShouldBeNil)
		So(length, ShouldEqual, len(wire))
		So(aPacket, ShouldResemble, ePacket)
	})
}
