package qtype

/*
   +----------+----------------------------------+
   | Low Bits | Stream Type                      |
   +----------+----------------------------------+
   | 0x0      | Client-Initiated, Bidirectional  |
   |          |                                  |
   | 0x1      | Server-Initiated, Bidirectional  |
   |          |                                  |
   | 0x2      | Client-Initiated, Unidirectional |
   |          |                                  |
   | 0x3      | Server-Initiated, Unidirectional |
   +----------+----------------------------------+
*/

type StreamID QuicInt

func NewStreamID(id uint64) (StreamID, error) {
	sid, err := NewQuicInt(id)
	if err != nil {
		return StreamID(QuicInt{0, 0, 0}), err
	}
	sss := StreamID(sid)
	return sss, err
}

func (s StreamID) GetValue() uint64 {
	qint := QuicInt(s)
	return qint.GetValue()
}

func (s StreamID) PutWire(wire []byte) int {
	return QuicInt(s).PutWire(wire)
}

func (s StreamID) String() string {
	return []string{
		"Client-Initiated, Bidirectional",
		"Server-Initiated, Bidirectional",
		"Client-Initiated, Unidirectional",
		"Server-Initiated, Unidirectional",
	}[QuicInt(s).Value&0x03]
}