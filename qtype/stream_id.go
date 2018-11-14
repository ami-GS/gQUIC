package qtype

import "fmt"

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

const (
	BidirectionalStream  = 0x0
	UnidirectionalStream = 0x2
)

func (s *StreamID) Increment() {
	// add 0b100
	*s = *s + 4
}

func (s StreamID) PutWire(wire []byte) int {
	return QuicInt(s).PutWire(wire)
}

func (s StreamID) String() string {
	return fmt.Sprintf("%s ID:%d", []string{
		"Client-Initiated, Bidirectional",
		"Server-Initiated, Bidirectional",
		"Client-Initiated, Unidirectional",
		"Server-Initiated, Unidirectional",
	}[s&0x03], s)
}
