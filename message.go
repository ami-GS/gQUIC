package quic

type Message struct {
	MsgTag QuicTag
	Tags   []QuicTag
	Values [][]byte
}

func NewMessage(msgTag QuicTag) (message *Message) {
	switch msgTag {
	case CHLO, SHLO, REJ:
		message = &Message{
			MsgTag: msgTag,
			Tags:   []QuicTag{},
			Values: [][]byte{},
		}
	}
	return nil
}

func (message *Message) AppendTagValue(tag QuicTag, value []byte) bool {
	switch tag {
	case CHLO, SHLO, REJ:
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

func (message *Message) GetWire() (wire []byte, err error) {
	valueLen := 0
	for _, v := range message.Values {
		valueLen += len(v)
	}
	tagNum := len(message.Tags)
	wire = make([]byte, 8+tagNum*8+valueLen)

	for i := 0; i < 4; i++ {
		wire[i] = byte(message.MsgTag >> byte(8*(3-i)))
	}
	for i := 0; i < 2; i++ {
		wire[4+i] = byte(tagNum >> byte(8*(1-i)))
	}
	// padding 0x0000

	index := 8
	endOffset := 0
	for i, tag := range message.Tags {
		endOffset += len(message.Values[i])
		for j := 0; j < 4; j++ {
			wire[index+j] = byte(tag >> byte(8*(3-j)))
			wire[index+4+j] = byte(endOffset >> byte(8*(3-j)))
		}
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
	message.MsgTag = QuicTag(data[0]<<24 | data[1]<<16 | data[2]<<8 | data[3])
	numPairs := uint16(data[4]<<8 | data[5])
	message.Tags = make([]QuicTag, numPairs)
	message.Values = make([][]byte, numPairs)
	var valueFrom uint32 = 8 + uint32(numPairs)*8
	index = 8

	var prevOffset uint32 = 0
	for i := 0; i < int(numPairs); i++ {
		message.Tags[i] = QuicTag(data[index]<<24 | data[index+1]<<16 | data[index+2]<<8 | data[index+3])
		endOffset := uint32(data[index+4]<<24 | data[index+5]<<16 | data[index+6]<<8 | data[index+7])
		message.Values[i] = make([]byte, endOffset-prevOffset)
		message.Values[i] = data[valueFrom:endOffset]
		valueFrom += endOffset
		prevOffset = endOffset
		index += 8
	}
	return
}
