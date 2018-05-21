package quiclatest

import (
	"testing"

	"github.com/ami-GS/gQUIC/latest/qtype"
	. "github.com/smartystreets/goconvey/convey"
)

func TestIsValidID(t *testing.T) {
	maxID, _ := qtype.NewStreamID(1000)
	manager := StreamManager{
		maxStreamID: maxID,
	}
	Convey("streamID bellow limit is safe", t, func() {
		sid, err := qtype.NewStreamID(0)
		err = manager.IsValidID(&sid)
		So(err, ShouldBeNil)
	})
	Convey("streamID over limit is error", t, func() {
		sid, err := qtype.NewStreamID(1001)
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
		maxID, _ := qtype.NewStreamID(1000)
		manager := NewStreamManager(nil)
		manager.maxStreamID = maxID
		// 1010: client initiated
		sid, _ := qtype.NewStreamID(10)
		aStream, err := manager.GetOrNewRecvStream(&sid, sess)
		eStream := newRecvStream(&sid, sess)
		So(err, ShouldBeNil)
		So(aStream, ShouldResemble, eStream)
	})

	Convey("If a stream created previously, it use the reference", t, func() {
		maxID, _ := qtype.NewStreamID(1000)
		manager := NewStreamManager(nil)
		manager.maxStreamID = maxID
		sid, _ := qtype.NewStreamID(10)
		eStream, _ := manager.GetOrNewRecvStream(&sid, sess)
		aStream, err := manager.GetOrNewRecvStream(&sid, sess)
		So(err, ShouldBeNil)
		So(aStream, ShouldResemble, eStream)
	})
	//TODO: error case about streamID
}

func TestIsTerminated(t *testing.T) {
	Convey("terminated if state is data read or reset read", t, func() {
		sid, _ := qtype.NewStreamID(10)
		stream := newRecvStream(&sid, nil)
		So(stream.IsTerminated(), ShouldBeFalse)
		stream.State = qtype.StreamDataRead
		So(stream.IsTerminated(), ShouldBeTrue)
		stream.State = qtype.StreamResetRead
		So(stream.IsTerminated(), ShouldBeTrue)
	})

	// TODO: after some handlers
}
