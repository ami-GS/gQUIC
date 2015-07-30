package quic

import (
	"reflect"
	"testing"
)

func TestMessage(t *testing.T) {
	version := "Q025"
	serverName := "S_NAME"
	data := []byte{'O', 'L', 'H', 'C', 0x00, 0x02, 0x00, 0x00,
		0x00, 'R', 'E', 'V', 0x00, 0x00, 0x00, 0x04,
		0x00, 'I', 'N', 'S', 0x00, 0x00, 0x00, 0x0a,
	}
	data = append(data, []byte(version)...)
	data = append(data, []byte(serverName)...)
	msg := &Message{}
	actualMsg := NewMessage(CHLO)
	actualMsg.AppendTagValue(VER, []byte(version))
	actualMsg.AppendTagValue(SNI, []byte(serverName))

	actualLen, _ := msg.Parse(data)
	if actualLen != len(data) {
		t.Errorf("got %v\nwant %v", actualLen, len(data))
	}

	if !reflect.DeepEqual(actualMsg, msg) {
		t.Errorf("got %v\nwant %v", actualMsg, msg)
	}

	actualWire, _ := msg.GetWire()
	if !reflect.DeepEqual(actualWire, data) {
		t.Errorf("got %v\nwant %v", actualWire, data)
	}

}
