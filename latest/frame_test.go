package quiclatest

import (
	"testing"

	"github.com/ami-GS/gQUIC/latest/qtype"
	. "github.com/smartystreets/goconvey/convey"
)

func TestFrameTypeString(t *testing.T) {
	Convey("if type 0x00 - 0x17, String should return properly", t, func() {
		testset := []string{
			"PADDING",
			"RST_STREAM",
			"CONNECTION_CLOSE",
			"APPLICATION_CLOSE",
			"MAX_DATA",
			"MAX_STREAM_DATA",
			"MAX_STREAM_ID",
			"PING",
			"BLOCKED",
			"STREAM_BLOCKED",
			"STREAM_ID_BLOCKED",
			"NEW_CONNECTION_ID",
			"STOP_WAITING",
			"ACK",
			"PATH_CHALLENGE",
			"PATH_RESPONSE",
			"STREAM",
			"STREAM",
			"STREAM",
			"STREAM",
			"STREAM",
			"STREAM",
			"STREAM",
			"STREAM",
			"NO_SUCH_TYPE",
		}
		for i := uint8(0); i < 0x18; i++ {
			ft := FrameType(i)
			So(ft.String(), ShouldEqual, testset[i])
		}
	})
}

func TestStreamFrame(t *testing.T) {
	Convey("NewStreamFrame returns stream frame", t, func() {
		sf1 := NewStreamFrame(0, 0, 1, false, true, false, []byte{0x01})
		sid, _ := qtype.NewQuicInt(0)
		ofst, _ := qtype.NewQuicInt(0)
		lngt, _ := qtype.NewQuicInt(1)
		sType := 0x12
		sfexpect := StreamFrame{NewBaseFrame(FrameType(sType)), qtype.StreamID(sid), ofst, lngt, false, []byte{0x01}}
		So(sf1, ShouldResemble, &sfexpect)
	})
}

func TestParseStreamFrame(t *testing.T) {
	// Data can be nil when OFF == 0 and/or FIN == true
	Convey("streamframetype:0x10, streamID:0, offset:absent, length:absent, data:fill all(only 0x00)", t, func() {
		data := []byte{0x10, 0x00, 0x00}
		aFrame, length, err := ParseStreamFrame(data)
		eFrame := NewStreamFrame(0, 0, 0, false, false, false, []byte{0x00})
		So(err, ShouldBeNil)
		So(length, ShouldEqual, 3)
		So(aFrame, ShouldResemble, eFrame)
	})
	Convey("streamframetype:0x14, streamID:0, offset:1, length:absent, data:fill all(only 0x00)", t, func() {
		data := []byte{0x14, 0x00, 0x01, 0x00}
		aFrame, length, err := ParseStreamFrame(data)
		eFrame := NewStreamFrame(0, 1, 0, true, false, false, []byte{0x00})
		So(err, ShouldBeNil)
		So(length, ShouldEqual, 4)
		So(aFrame, ShouldResemble, eFrame)
	})
	Convey("streamframetype:0x14, streamID:0, offset:0, length:absent, data:nil", t, func() {
		data := []byte{0x14, 0x00, 0x00}
		aFrame, length, err := ParseStreamFrame(data)
		eFrame := NewStreamFrame(0, 0, 0, true, false, false, nil)
		So(err, ShouldBeNil)
		So(length, ShouldEqual, 3)
		So(aFrame, ShouldResemble, eFrame)
	})
	Convey("streamframetype:0x12, streamID:0, offset:absent, length:1, data:0x00", t, func() {
		data := []byte{0x12, 0x00, 0x01, 0x00}
		aFrame, length, err := ParseStreamFrame(data)
		eFrame := NewStreamFrame(0, 0, 1, false, true, false, []byte{0x00})
		So(err, ShouldBeNil)
		So(length, ShouldEqual, 4)
		So(aFrame, ShouldResemble, eFrame)
	})
	Convey("streamframetype:0x17, streamID:0, offset:absent, length:absent, data:nil", t, func() {
		data := []byte{0x11, 0x00}
		aFrame, length, err := ParseStreamFrame(data)
		eFrame := NewStreamFrame(0, 0, 0, false, false, true, nil)
		So(err, ShouldBeNil)
		So(length, ShouldEqual, 2)
		So(aFrame, ShouldResemble, eFrame)
	})
	Convey("streamframetype:0x16, streamID:0, offset:0, length:0, data:fill all(only 0x00)", t, func() {
		data := []byte{0x14, 0x00, 0x00, 0x00}
		aFrame, length, err := ParseStreamFrame(data)
		eFrame := NewStreamFrame(0, 0, 0, true, false, false, []byte{0x00})
		So(err, ShouldBeNil)
		So(length, ShouldEqual, 4)
		So(aFrame, ShouldResemble, eFrame)
	})
}

func TestGetWireOfStreamFrame(t *testing.T) {
	Convey("streamframetype:0x10, streamID:0, offset:absent, length:absent, data:fill all(only 0x00)", t, func() {
		eWire := []byte{0x10, 0x00, 0x00}
		Frame := NewStreamFrame(0, 0, 0, false, false, false, []byte{0x00})
		aWire, err := Frame.GetWire()
		So(err, ShouldBeNil)
		So(aWire, ShouldResemble, eWire)
	})
	Convey("streamframetype:0x14, streamID:0, offset:1, length:absent, data:fill all(only 0x00)", t, func() {
		eWire := []byte{0x14, 0x00, 0x01, 0x00}
		Frame := NewStreamFrame(0, 1, 0, true, false, false, []byte{0x00})
		aWire, err := Frame.GetWire()
		So(err, ShouldBeNil)
		So(aWire, ShouldResemble, eWire)
	})

	Convey("streamframetype:0x14, streamID:0, offset:0, length:absent, data:nil", t, func() {
		eWire := []byte{0x14, 0x00, 0x00}
		Frame := NewStreamFrame(0, 0, 0, true, false, false, nil)
		aWire, err := Frame.GetWire()
		So(err, ShouldBeNil)
		So(aWire, ShouldResemble, eWire)
	})
	Convey("streamframetype:0x12, streamID:0, offset:absent, length:1, data:0x00", t, func() {
		eWire := []byte{0x12, 0x00, 0x01, 0x00}
		Frame := NewStreamFrame(0, 0, 1, false, true, false, []byte{0x00})
		aWire, err := Frame.GetWire()
		So(err, ShouldBeNil)
		So(aWire, ShouldResemble, eWire)
	})

	Convey("streamframetype:0x17, streamID:0, offset:absent, length:absent, data:nil", t, func() {
		eWire := []byte{0x11, 0x00}
		Frame := NewStreamFrame(0, 0, 0, false, false, true, nil)
		aWire, err := Frame.GetWire()
		So(err, ShouldBeNil)
		So(aWire, ShouldResemble, eWire)
	})

	Convey("streamframetype:0x16, streamID:0, offset:0, length:0, data:fill all(only 0x00)", t, func() {
		eWire := []byte{0x14, 0x00, 0x00, 0x00}
		Frame := NewStreamFrame(0, 0, 0, true, false, false, []byte{0x00})
		aWire, err := Frame.GetWire()
		So(err, ShouldBeNil)
		So(aWire, ShouldResemble, eWire)
	})
}
