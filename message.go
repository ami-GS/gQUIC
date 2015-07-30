package quic

import (
	"encoding/binary"
	//"fmt"
	//	"reflect"
)

type Message struct {
	MsgTag QuicTag
	Tags   []QuicTag
	Values [][]byte
}

func NewMessage(msgTag QuicTag) *Message {
	switch msgTag {
	case CHLO, SHLO, REJ, PRST:
		message := &Message{
			MsgTag: msgTag,
			Tags:   []QuicTag{},
			Values: [][]byte{},
		}
		return message
	}
	return nil
}

func (message *Message) AppendTagValue(tag QuicTag, value []byte) bool {
	switch tag {
	case CHLO, SHLO, REJ, PRST:
		return false
	}
	if !message.TagContain(tag) {
		message.Tags = append(message.Tags, tag)
		message.Values = append(message.Values, value)
		return true
	}
	return false
}

func (message *Message) TagContain(tag QuicTag) bool {
	for _, t := range message.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

func (message *Message) SortTags() {
	// TODO: consider that here should be quick sort
	tagNum := len(message.Tags)
	for i := 0; i < tagNum-1; i++ {
		for j := tagNum - 1; j > i; j-- {
			if message.Tags[j-1] < message.Tags[j] {
				tmpT := message.Tags[j]
				message.Tags[j] = message.Tags[j-1]
				message.Tags[j-1] = tmpT
				tmpV := message.Values[j]
				message.Values[j] = message.Values[j-1]
				message.Values[j-1] = tmpV
			}
		}
	}
}

func (message *Message) GetWire() (wire []byte, err error) {
	message.SortTags()

	valueLen := 0
	for _, v := range message.Values {
		valueLen += len(v)
	}
	tagNum := len(message.Tags)
	wire = make([]byte, 8+tagNum*8+valueLen)

	binary.BigEndian.PutUint32(wire, uint32(message.MsgTag))
	binary.BigEndian.PutUint16(wire[4:], uint16(tagNum))
	// padding 0x0000

	index := 8
	var endOffset uint32 = 0
	for i, tag := range message.Tags {
		endOffset += uint32(len(message.Values[i]))
		binary.BigEndian.PutUint32(wire[index:], uint32(tag))
		binary.BigEndian.PutUint32(wire[index+4:], endOffset)
		index += 8
	}
	for _, value := range message.Values {
		valLen := len(value)
		for j := 0; j < valLen; j++ {
			wire[index+j] = value[j]
		}
		index += valLen
	}
	return
}

func (message *Message) Parse(data []byte) (index int, err error) {
	message.MsgTag = QuicTag(binary.BigEndian.Uint32(data[0:4]))
	numPairs := binary.BigEndian.Uint16(data[4:6])
	message.Tags = make([]QuicTag, numPairs)
	message.Values = make([][]byte, numPairs)
	var valueFrom uint32 = 8 + uint32(numPairs)*8
	index = 8
	var prevOffset, endOffset uint32
	for i := 0; i < int(numPairs); i++ {
		message.Tags[i] = QuicTag(binary.BigEndian.Uint32(data[index : index+4]))
		endOffset = binary.BigEndian.Uint32(data[index+4:])
		message.Values[i] = make([]byte, endOffset-prevOffset)
		message.Values[i] = data[valueFrom : valueFrom+endOffset-prevOffset]
		valueFrom += endOffset
		prevOffset = endOffset
		index += 8
	}
	index += int(endOffset)

	message.SortTags()
	return
}
