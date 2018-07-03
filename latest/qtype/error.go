package qtype

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
	FrameFormatError
	TransportParameterError
	VersionNegotiationError
	ProtocolViolation
	UnsolicitedPathResponse

	// not defined the value in spec 11
	FlowControlReceivedTooMuchData

	FrameError = 0x100 // 0x1XX, the XX will be frame type
)

func (e TransportError) Error() string {
	if e >= FrameError {
		// TODO: solve import cycle by separating file of FrameType implementation
		return "FrameError: " // + quiclatest.FrameType(uint16(e)&0xff).String()
	}
	return []string{
		"NoError",
		"InternalError",
		"ServerBusy",
		"FlowControlError",
		"StreamIDError",
		"StreamStateError",
		"FinalOffsetError",
		"FrameFormatError",
		"TransportParameterError",
		"VersionNegotiationError",
		"ProtocolViolation",
		"UnsolicitedPathResponse",
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
