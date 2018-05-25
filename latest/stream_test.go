package quiclatest

import (
	"testing"

	"github.com/ami-GS/gQUIC/latest/qtype"
	. "github.com/smartystreets/goconvey/convey"
)

func TestIsValidID(t *testing.T) {
	maxIDUni, _ := qtype.NewStreamID(1000)
	maxIDBidi, _ := qtype.NewStreamID(1001)
	manager := StreamManager{
		maxStreamIDUni:  maxIDUni,
		maxStreamIDBidi: maxIDBidi,
	}
	Convey("uni streamID bellow limit is safe", t, func() {
		sid, err := qtype.NewStreamID(2)
		err = manager.IsValidID(&sid)
		So(err, ShouldBeNil)
	})
	Convey("uni streamID over limit is error", t, func() {
		sid, err := qtype.NewStreamID(1002)
		err = manager.IsValidID(&sid)
		So(err, ShouldEqual, qtype.StreamIDError)
	})
	Convey("bidi streamID bellow limit is safe", t, func() {
		sid, err := qtype.NewStreamID(1)
		err = manager.IsValidID(&sid)
		So(err, ShouldBeNil)
	})
	Convey("uni streamID over limit is error", t, func() {
		sid, err := qtype.NewStreamID(1003)
		err = manager.IsValidID(&sid)
		So(err, ShouldEqual, qtype.StreamIDError)
	})
}

func testnewRecvStream(t *testing.T) {
	destID, _ := qtype.NewConnectionID(nil)
	srcID, _ := qtype.NewConnectionID(nil)
	sess := NewSession(nil, destID, srcID)
	Convey("newRecvStream", t, func() {
		sid, _ := qtype.NewStreamID(10)
		aStream := newRecvStream(&sid, sess)
		eStream := &RecvStream{
			BaseStream: &BaseStream{
				ID:    sid,
				State: qtype.StreamRecv,
				sess:  sess,
			},
		}
		So(aStream, ShouldResemble, eStream)
	})
}

func TestGetOrNewRecvStream(t *testing.T) {
	destID, _ := qtype.NewConnectionID(nil)
	srcID, _ := qtype.NewConnectionID(nil)
	sess := NewSession(nil, destID, srcID)
	Convey("If no stream created, new stream will be taken", t, func() {
		maxIDUni, _ := qtype.NewStreamID(1000)
		maxIDBidi, _ := qtype.NewStreamID(1001)
		manager := NewStreamManager(nil)
		manager.maxStreamIDUni = maxIDUni
		manager.maxStreamIDBidi = maxIDBidi
		// 1010: client initiated
		sid, _ := qtype.NewStreamID(10)
		aStream, isNew, err := manager.GetOrNewRecvStream(&sid, sess)
		eStream := newRecvStream(&sid, sess)
		So(isNew, ShouldBeTrue)
		So(err, ShouldBeNil)
		So(aStream, ShouldResemble, eStream)
	})

	Convey("If a stream created previously, it use the reference", t, func() {
		maxIDUni, _ := qtype.NewStreamID(1000)
		maxIDBidi, _ := qtype.NewStreamID(1001)
		manager := NewStreamManager(nil)
		manager.maxStreamIDUni = maxIDUni
		manager.maxStreamIDBidi = maxIDBidi
		sid, _ := qtype.NewStreamID(10)
		eStream, isNewRcv, err := manager.GetOrNewRecvStream(&sid, sess)
		So(isNewRcv, ShouldBeTrue)
		So(err, ShouldBeNil)
		aStream, isNewRcv, err := manager.GetOrNewRecvStream(&sid, sess)
		So(isNewRcv, ShouldBeFalse)
		So(err, ShouldBeNil)
		So(aStream, ShouldResemble, eStream)
	})
	//TODO: error case about streamID
}

func TestIsTerminated(t *testing.T) {
	destID, _ := qtype.NewConnectionID(nil)
	srcID, _ := qtype.NewConnectionID(nil)
	sess := NewSession(nil, destID, srcID)
	Convey("terminated if state is data read or reset read", t, func() {
		sid, _ := qtype.NewStreamID(10)
		stream := newRecvStream(&sid, sess)
		So(stream.IsTerminated(), ShouldBeFalse)
		stream.State = qtype.StreamDataRead
		So(stream.IsTerminated(), ShouldBeTrue)
		stream.State = qtype.StreamResetRead
		So(stream.IsTerminated(), ShouldBeTrue)
	})

	// TODO: after some handlers
}
