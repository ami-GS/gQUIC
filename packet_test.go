package quic

import (
	"reflect"
	"testing"
)

func TestPacketHeader(t *testing.T) {
	// pubFlag:5 ConnID: 1, version: 1, seqNum:1, privateFlag:0, fec:1
	data := []byte{0x05, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00}
	//
	actualHeader := NewPacketHeader(VersionNegotiationPacketType, 1, 1, 1, 0)
	header := &PacketHeader{}

	actualLen, _ := header.Parse(data)
	if actualLen != len(data) {
		t.Errorf("got %v\nwant %v", actualLen, len(data))
	}

	if !reflect.DeepEqual(actualHeader, header) {
		t.Errorf("got %v\nwant %v", actualHeader, header)
	}

	actualWire, _ := header.GetWire()
	if !reflect.DeepEqual(actualWire, data) {
		t.Errorf("got %v\nwant %v", actualWire, data)
	}
}

func TestFramePacket(t *testing.T) {
	data := []byte{
		//header, pubFlag:4, connID:1, seqNum:1, priFlag:0
		0x04, 0x01, 0x01, 0x00,
		// stream, fin:true, stID:1, offset:1, dataLength:1
		0xe4, 0x01, 0x00, 0x01, 0x00, 0x05, 'a', 'i', 'u', 'e', 'o',
		// window update, stID:1, offset:1
		0x04, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	actual_ph, idx, _ := ParsePacketHeader(data)
	packet, actualLen := PacketParserMap[actual_ph.Type](actual_ph, data[idx:])
	ph := NewPacketHeader(FramePacketType, 1, 0, 1, 0)
	actualPacket := NewFramePacket(1, 1)
	actualPacket.PacketHeader = ph
	f1 := NewStreamFrame(true, 1, 1, []byte("aiueo"))
	f1.FramePacket = actualPacket
	f2 := NewWindowUpdateFrame(1, 1)
	f2.FramePacket = actualPacket
	actualPacket.PushBack(f1)
	actualPacket.PushBack(f2)
	actualWire, _ := packet.GetWire()

	if actualLen+4 != len(data) {
		t.Errorf("got %v\nwant %v", actualLen, len(data))
	}

	if !reflect.DeepEqual(actualPacket, packet) {
		t.Errorf("got %v\nwant %v", actualPacket, packet)
	}

	if !reflect.DeepEqual(actualWire, data) {
		t.Errorf("got %v\nwant %v", actualWire, data)
	}
}
