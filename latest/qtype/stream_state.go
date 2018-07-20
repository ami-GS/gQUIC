package qtype

type StreamState uint8


const (
	StreamReady StreamState = iota
	StreamRecv
	StreamSend
	StreamDataSent
	StreamSizeKnown
	StreamDataRecvd
	StreamDataRead
	StreamResetSent
	StreamResetRecvd
	StreamResetRead

	StreamOpen
	StreamIdle
	StreamClosed
	StreamHalfClosed
)

func (s StreamState) String() string {
	return []string{
		"Ready",
		"Recv",
		"Send",
		"Data Sent",
		"Size Known",
		"Data Recvd",
		"Data Read",
		"Reset Sent",
		"Reset Recvd",
		"Reset Read",

		"Idle",
		"Open",
		"Half Closed",
		"Closed",
	}[s]
}
