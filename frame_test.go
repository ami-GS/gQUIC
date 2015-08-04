package quic

import (
	"reflect"
	"testing"
)

func TestStreamFrameFrame(t *testing.T) {
	// fin: true, streamID: 1, offset: 1, dataLength: 1
	data := []byte{0xe4, 0x01, 0x00, 0x01, 0x00, 0x05}
	testD := []byte("aiueo")
	data = append(data, testD...)
	fp := NewFramePacket(0, 0)
	frame := &StreamFrame{FramePacket: fp}
	actualFrame := NewStreamFrame(true, 1, 1, testD)
	actualFrame.SetPacket(fp)

	actualLen, _ := frame.Parse(data)
	if actualLen != len(data) {
		t.Errorf("got %v\nwant %v", actualLen, len(data))
	}

	if !reflect.DeepEqual(actualFrame, frame) {
		t.Errorf("got %v\nwant %v", actualFrame, frame)
	}

	actualWire, _ := frame.GetWire()
	if !reflect.DeepEqual(actualWire, data) {
		t.Errorf("got %v\nwant %v", actualWire, data)
	}
}

func TestPaddingFrame(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00, 0x00}
	fp := NewFramePacket(0, 0)
	fp.DataSize = 1945
	fp.RestSize = 5
	frame := &PaddingFrame{FramePacket: fp}
	actualFrame := NewPaddingFrame()
	actualFrame.SetPacket(fp)

	actualLen, _ := frame.Parse(data)
	if actualLen != len(data) {
		t.Errorf("got %v\nwant %v", actualLen, len(data))
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
	// streamID:1, offset:1, errorcode: NO_ERROR
	data := []byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	fp := NewFramePacket(0, 0)
	frame := &RstStreamFrame{FramePacket: fp}
	actualFrame := NewRstStreamFrame(1, 1, NO_ERROR)
	actualFrame.SetPacket(fp)

	actualLen, _ := frame.Parse(data)
	if actualLen != len(data) {
		t.Errorf("got %v\nwant %v", actualLen, len(data))
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
	frame := &PingFrame{FramePacket: fp}
	actualFrame := NewPingFrame()
	actualFrame.SetPacket(fp)

	actualLen, _ := frame.Parse(data)
	if actualLen != len(data) {
		t.Errorf("got %v\nwant %v", actualLen, len(data))
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
	// errorcode: NO_ERROR, reason length: 14, reason: "This is reason",
	data := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e}
	reason := "This is reason"
	data = append(data, []byte(reason)...)
	fp := NewFramePacket(0, 0)
	frame := &ConnectionCloseFrame{FramePacket: fp}
	actualFrame := NewConnectionCloseFrame(NO_ERROR, reason)
	actualFrame.SetPacket(fp)

	actualLen, _ := frame.Parse(data)
	if actualLen != len(data) {
		t.Errorf("got %v\nwant %v", actualLen, len(data))
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
	// errorcode: NO_ERROR, last streamID: 1, reason length: 14, reason: "This is reason",
	data := []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0e}
	reason := "This is reason"
	data = append(data, []byte(reason)...)
	fp := NewFramePacket(0, 0)
	frame := &GoAwayFrame{FramePacket: fp}
	actualFrame := NewGoAwayFrame(NO_ERROR, 1, reason)
	actualFrame.SetPacket(fp)

	actualLen, _ := frame.Parse(data)
	if actualLen != len(data) {
		t.Errorf("got %v\nwant %v", actualLen, len(data))
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
	frame := &WindowUpdateFrame{FramePacket: fp}
	actualFrame := NewWindowUpdateFrame(1, 1)
	actualFrame.SetPacket(fp)

	actualLen, _ := frame.Parse(data)
	if actualLen != len(data) {
		t.Errorf("got %v\nwant %v", actualLen, len(data))
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
	frame := &BlockedFrame{FramePacket: fp}
	actualFrame := NewBlockedFrame(1)
	actualFrame.SetPacket(fp)

	actualLen, _ := frame.Parse(data)
	if actualLen != len(data) {
		t.Errorf("got %v\nwant %v", actualLen, len(data))
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
	// Sent Entropy: 1, least unacked delta: 1
	data := []byte{0x06, 0x01, 0x01}
	fp := NewFramePacket(0, 0)
	frame := &StopWaitingFrame{FramePacket: fp}
	actualFrame := NewStopWaitingFrame(1, 1)
	actualFrame.SetPacket(fp)

	actualLen, _ := frame.Parse(data)
	if actualLen != len(data) {
		t.Errorf("got %v\nwant %v", actualLen, len(data))
	}

	if !reflect.DeepEqual(actualFrame, frame) {
		t.Errorf("got %v\nwant %v", actualFrame, frame)
	}

	actualWire, _ := frame.GetWire()
	if !reflect.DeepEqual(actualWire, data) {
		t.Errorf("got %v\nwant %v", actualWire, data)
	}

}
