package error

import "math"

// used in CONNECTION_CLOSE frame
type TransportError uint16

const (
	NoError TransportError = iota
	InternalError
	ServerBusy
	FlowControlError
	StreamIDError
	StreamStateError
	FinalOffsetError
	FrameEncodingError
	TransportParameterError
	VersionNegotiationError
	ProtocolViolation
	InvalidMigration = 0xc

	CryptoError = 0x100 // 0x1XX, XX is reserved for carrying error codes specific to the cryptographic handshake
)

func (e TransportError) Error() string {
	if e >= CryptoError {
		// TODO: solve import cycle by separating file of FrameType implementation
		return "CryptoError: " // + quiclatest.FrameType(uint16(e)&0xff).String()
	}
	return []string{
		"NoError",
		"InternalError",
		"ServerBusy",
		"FlowControlError",
		"StreamIDError",
		"StreamStateError",
		"FinalOffsetError",
		"FrameEncodingError",
		"TransportParameterError",
		"VersionNegotiationError",
		"ProtocolViolation",
		"_",
		"InvalidMigration",
	}[e]
}

// only 0 is reserved for STOPPING
type ApplicationError uint16

const (
	Stopping             ApplicationError = iota
	ApplicationErrorTest ApplicationError = math.MaxUint16
)

func (e ApplicationError) Error() string {
	if e == ApplicationErrorTest {
		return "Application Error Test"
	}
	return []string{
		"Stopping",
	}[e]
}
