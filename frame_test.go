package quic

import (
	"reflect"
	"testing"
)

func TestAckFrame(t *testing.T) {
	data := [][]byte{
		// 0b0100 0000, LAcked:0, LAckedDelta:0, NumTimeStamp:0,
		[]byte{0x40, 0x00, 0x00, 0x00, 0x00},
		// 0b0100 0000, LAcked:0, LAckedDelta:0, NumTimeStamp:1,
		//[]byte{0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
	fp := NewFramePacket(0, 0)
	actualFrames := []*AckFrame{
		NewAckFrame(0, 0, 0, nil, nil, nil),
		/*
			NewAckFrame(0, 0, 0, nil, &FirstTimestamp{
				DeltaLargestAcked:     0,
				TimeSinceLargestAcked: 0,
			}, nil),
		*/
	}

	for i, d := range data {
		frame, _ := FrameParserMap[FrameType(d[0]&AckFrameType)](fp, d)
		actualFrame := actualFrames[i]
		actualFrame.FramePacket = fp

		wire, _ := actualFrame.GetWire()
		if len(wire) != len(d) {
			t.Errorf("got %v\nwant %v", len(wire), len(d))
		}
		/*
			if !reflect.DeepEqual(actualFrame, frame) {
				t.Errorf("got %v\nwant %v", actualFrame, frame)
			}
		*/
		actualWire, _ := frame.GetWire()
		if !reflect.DeepEqual(actualWire, d) {
			t.Errorf("got %v\nwant %v", actualWire, d)
		}
	}
}

func TestStreamFrame(t *testing.T) {
	// fin: true, streamID: 1, offset: 1, dataLength: 1
	//data := []byte{0xe4, 0x01, 0x00, 0x01, 0x00, 0x05}
	data := [][]byte{
		// fin: true, streamID: 1, offset: 1, dataLength: 1
		[]byte{0xe4, 0x01, 0x00, 0x01, 0x00, 0x05},
		// fin: false, streamID: 256, offset 0, dataLength: 1
		[]byte{0xa1, 0x01, 0x00, 0x00, 0x05},
	}

	testD := []byte("aiueo")
	fp := NewFramePacket(0, 0)
	actualFrames := []*StreamFrame{
		NewStreamFrame(true, 1, 1, testD),
		NewStreamFrame(false, 256, 0, testD),
	}
	for i, d := range data {
		d := append(d, testD...)
		frame, _ := FrameParserMap[FrameType(d[0]&StreamFrameType)](fp, d)
		actualFrame := actualFrames[i]
		actualFrame.FramePacket = fp

		wire, _ := actualFrame.GetWire()
		if len(wire) != len(d) {
			t.Errorf("got %v\nwant %v", len(wire), len(d))
		}

		if !reflect.DeepEqual(actualFrame, frame) {
			t.Errorf("got %v\nwant %v", actualFrame, frame)
		}

		actualWire, _ := frame.GetWire()
		if !reflect.DeepEqual(actualWire, d) {
			t.Errorf("got %v\nwant %v", actualWire, d)
		}

	}
}

func TestPaddingFrame(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00, 0x00}
	fp := NewFramePacket(0, 0)
	fp.DataSize = 1945
	fp.RestSize = 5

	frame, _ := FrameParserMap[FrameType(data[0])](fp, data)
	actualFrame := NewPaddingFrame()
	actualFrame.FramePacket = fp

	wire, _ := actualFrame.GetWire()
	if len(wire) != len(data) {
		t.Errorf("got %v\nwant %v", len(wire), len(data))
	}

	if !reflect.DeepEqual(actualFrame, frame) {
		t.Errorf("got %v\nwant %v", actualFrame, frame)
	}

	actualWire, _ := frame.GetWire()
	if !reflect.DeepEqual(actualWire, data) {
		t.Errorf("got %v\nwant %v", actualWire, data)
	}

}

func TestRstStreamFrame(t *testing.T) {
	// streamID:1, offset:1, errorcode: QUIC_NO_ERROR
	data := []byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	fp := NewFramePacket(0, 0)

	frame, _ := FrameParserMap[FrameType(data[0])](fp, data)
	actualFrame := NewRstStreamFrame(1, 1, QUIC_NO_ERROR)
	actualFrame.FramePacket = fp

	wire, _ := actualFrame.GetWire()
	if len(wire) != len(data) {
		t.Errorf("got %v\nwant %v", len(wire), len(data))
	}

	if !reflect.DeepEqual(actualFrame, frame) {
		t.Errorf("got %v\nwant %v", actualFrame, frame)
	}

	actualWire, _ := frame.GetWire()
	if !reflect.DeepEqual(actualWire, data) {
		t.Errorf("got %v\nwant %v", actualWire, data)
	}
}

func TestPingFrame(t *testing.T) {
	data := []byte{0x07}
	fp := NewFramePacket(0, 0)

	frame, _ := FrameParserMap[FrameType(data[0])](fp, data)
	actualFrame := NewPingFrame()
	actualFrame.FramePacket = fp

	wire, _ := actualFrame.GetWire()
	if len(wire) != len(data) {
		t.Errorf("got %v\nwant %v", len(wire), len(data))
	}

	if !reflect.DeepEqual(actualFrame, frame) {
		t.Errorf("got %v\nwant %v", actualFrame, frame)
	}

	actualWire, _ := frame.GetWire()
	if !reflect.DeepEqual(actualWire, data) {
		t.Errorf("got %v\nwant %v", actualWire, data)
	}
}

func TestConnectionCloseFrame(t *testing.T) {
	// errorcode: QUIC_NO_ERROR, reason length: 14, reason: "This is reason",
	data := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e}
	reason := "This is reason"
	data = append(data, []byte(reason)...)
	fp := NewFramePacket(0, 0)
	frame, _ := FrameParserMap[FrameType(data[0])](fp, data)
	actualFrame := NewConnectionCloseFrame(QUIC_NO_ERROR, reason)
	actualFrame.FramePacket = fp

	wire, _ := actualFrame.GetWire()
	if len(wire) != len(data) {
		t.Errorf("got %v\nwant %v", len(wire), len(data))
	}

	if !reflect.DeepEqual(actualFrame, frame) {
		t.Errorf("got %v\nwant %v", actualFrame, frame)
	}

	actualWire, _ := frame.GetWire()
	if !reflect.DeepEqual(actualWire, data) {
		t.Errorf("got %v\nwant %v", actualWire, data)
	}
}

func TestGoAwayFrame(t *testing.T) {
	// errorcode: QUIC_NO_ERROR, last streamID: 1, reason length: 14, reason: "This is reason",
	data := []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0e}
	reason := "This is reason"
	data = append(data, []byte(reason)...)
	fp := NewFramePacket(0, 0)
	frame, _ := FrameParserMap[FrameType(data[0])](fp, data)
	actualFrame := NewGoAwayFrame(QUIC_NO_ERROR, 1, reason)
	actualFrame.FramePacket = fp

	wire, _ := actualFrame.GetWire()
	if len(wire) != len(data) {
		t.Errorf("got %v\nwant %v", len(wire), len(data))
	}

	if !reflect.DeepEqual(actualFrame, frame) {
		t.Errorf("got %v\nwant %v", actualFrame, frame)
	}

	actualWire, _ := frame.GetWire()
	if !reflect.DeepEqual(actualWire, data) {
		t.Errorf("got %v\nwant %v", actualWire, data)
	}

}

func TestWindowUpdateFrame(t *testing.T) {
	// streamID: 1, offset 1
	data := []byte{0x04, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	fp := NewFramePacket(0, 0)
	frame, _ := FrameParserMap[FrameType(data[0])](fp, data)
	actualFrame := NewWindowUpdateFrame(1, 1)
	actualFrame.FramePacket = fp

	wire, _ := actualFrame.GetWire()
	if len(wire) != len(data) {
		t.Errorf("got %v\nwant %v", len(wire), len(data))
	}

	if !reflect.DeepEqual(actualFrame, frame) {
		t.Errorf("got %v\nwant %v", actualFrame, frame)
	}

	actualWire, _ := frame.GetWire()
	if !reflect.DeepEqual(actualWire, data) {
		t.Errorf("got %v\nwant %v", actualWire, data)
	}

}

func TestBlockedFrame(t *testing.T) {
	// streamID: 1
	data := []byte{0x05, 0x00, 0x00, 0x00, 0x01}
	fp := NewFramePacket(0, 0)
	frame, _ := FrameParserMap[FrameType(data[0])](fp, data)
	actualFrame := NewBlockedFrame(1)
	actualFrame.FramePacket = fp

	wire, _ := actualFrame.GetWire()
	if len(wire) != len(data) {
		t.Errorf("got %v\nwant %v", len(wire), len(data))
	}

	if !reflect.DeepEqual(actualFrame, frame) {
		t.Errorf("got %v\nwant %v", actualFrame, frame)
	}

	actualWire, _ := frame.GetWire()
	if !reflect.DeepEqual(actualWire, data) {
		t.Errorf("got %v\nwant %v", actualWire, data)
	}
}

func TestStopWaitingFrame(t *testing.T) {
	data := [][]byte{
		// Sent Entropy: 1, least unacked delta: 1
		[]byte{0x06, 0x01},
		// Sent Entropy: 0, least unacked delta: 257
		[]byte{0x06, 0x01, 0x01},
	}
	fp := NewFramePacket(0, 0)
	actualFrames := []*StopWaitingFrame{
		NewStopWaitingFrame(1),
		NewStopWaitingFrame(257),
	}

	for i, d := range data {
		if i == 1 {
			fp.PacketHeader.PublicFlags |= PACKET_NUMBER_LENGTH_2
		}
		frame, _ := FrameParserMap[FrameType(d[0])](fp, d)
		actualFrame := actualFrames[i]
		actualFrame.FramePacket = fp

		wire, _ := actualFrame.GetWire()
		if len(wire) != len(d) {
			t.Errorf("got %v\nwant %v", len(wire), len(d))
		}

		if !reflect.DeepEqual(actualFrame, frame) {
			t.Errorf("got %v\nwant %v", actualFrame, frame)
		}

		actualWire, _ := frame.GetWire()
		if !reflect.DeepEqual(actualWire, d) {
			t.Errorf("got %v\nwant %v", actualWire, d)
		}
	}
}
