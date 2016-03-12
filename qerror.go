package quic

type QUIC_ERROR uint16

const (
	FAIL_TO_SET_CONNECTION_ID QUIC_ERROR = iota
)

func (e QUIC_ERROR) Error() string {
	return []string{
		"FAIL_TO_SET_CONNECTION_ID",
	}[e]
}
