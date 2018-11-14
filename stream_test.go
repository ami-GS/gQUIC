package quic

import (
	"testing"

	"github.com/ami-GS/gQUIC/qtype"
	. "github.com/smartystreets/goconvey/convey"
)

func TestIsValidID(t *testing.T) {
	manager := StreamManager{
		maxStreamIDUni:  qtype.StreamID(1000),
		maxStreamIDBidi: qtype.StreamID(1001),
	}
	Convey("uni streamID bellow limit is safe", t, func() {
		err := manager.IsValidID(qtype.StreamID(2))
		So(err, ShouldBeNil)
	})
	Convey("uni streamID over limit is error", t, func() {
		err := manager.IsValidID(qtype.StreamID(1002))
		So(err, ShouldEqual, qtype.StreamIDError)
	})
	Convey("bidi streamID bellow limit is safe", t, func() {
		err := manager.IsValidID(qtype.StreamID(1))
		So(err, ShouldBeNil)
	})
	Convey("uni streamID over limit is error", t, func() {
		err := manager.IsValidID(qtype.StreamID(1003))
		So(err, ShouldEqual, qtype.StreamIDError)
	})
}

func testnewRecvStream(t *testing.T) {
	destID, _ := qtype.NewConnectionID(nil)
	srcID, _ := qtype.NewConnectionID(nil)
	sess := NewSession(nil, destID, srcID, true)
	Convey("newRecvStream", t, func() {
		aStream := newRecvStream(qtype.StreamID(10), sess)
		eStream := &RecvStream{
			BaseStream: &BaseStream{
				ID:    qtype.StreamID(10),
				State: qtype.StreamRecv,
				sess:  sess,
			},
		}
		So(aStream, ShouldResemble, eStream)
	})
}

func TestGetOrNewStream(t *testing.T) {
	destID, _ := qtype.NewConnectionID(nil)
	srcID, _ := qtype.NewConnectionID(nil)
	Convey("If no stream created, new stream will be taken", t, func() {
		sess := NewSession(nil, destID, srcID, true)
		manager := NewStreamManager(sess)
		manager.maxStreamIDUni = qtype.StreamID(1000)
		manager.maxStreamIDBidi = qtype.StreamID(1001)
		// 1010: client initiated
		aStream, isNew, err := manager.GetOrNewStream(qtype.StreamID(10), false)
		_, ok := aStream.(*RecvStream)
		eStream := newRecvStream(qtype.StreamID(10), sess)
		So(ok, ShouldBeTrue)
		So(isNew, ShouldBeTrue)
		So(err, ShouldBeNil)
		So(aStream, ShouldResemble, eStream)
	})

	Convey("If a stream created previously, it use the reference", t, func() {
		sess := NewSession(nil, destID, srcID, true)
		manager := NewStreamManager(sess)
		manager.maxStreamIDUni = qtype.StreamID(1000)
		manager.maxStreamIDBidi = qtype.StreamID(1001)
		eStream, isNewRcv, err := manager.GetOrNewStream(qtype.StreamID(10), false)
		_, ok := eStream.(*RecvStream)
		So(ok, ShouldBeTrue)
		So(isNewRcv, ShouldBeTrue)
		So(err, ShouldBeNil)
		aStream, isNewRcv, err := manager.GetOrNewStream(qtype.StreamID(10), false)
		_, ok = eStream.(*RecvStream)
		So(ok, ShouldBeTrue)
		So(isNewRcv, ShouldBeFalse)
		So(err, ShouldBeNil)
		So(aStream, ShouldResemble, eStream)
	})
	//TODO: error case about streamID
}

func TestIsTerminated(t *testing.T) {
	destID, _ := qtype.NewConnectionID(nil)
	srcID, _ := qtype.NewConnectionID(nil)
	sess := NewSession(nil, destID, srcID, true)
	Convey("terminated if state is data read or reset read", t, func() {
		stream := newRecvStream(qtype.StreamID(10), sess)
		So(stream.IsTerminated(), ShouldBeFalse)
		stream.State = qtype.StreamDataRead
		So(stream.IsTerminated(), ShouldBeTrue)
		stream.State = qtype.StreamResetRead
		So(stream.IsTerminated(), ShouldBeTrue)
	})

	// TODO: after some handlers
}
