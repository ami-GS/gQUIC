package quiclatest

import "github.com/ami-GS/gQUIC/latest/qtype"

type baseFlowController struct {
	bytesSent       uint64
	bytesReceived   uint64
	largestSent     uint64
	largestReceived uint64

	MaxDataLimit uint64
}

type StreamFlowController struct {
	IsStreamZero bool
	baseFlowController
	connFC *ConnectionFlowController
}

type FlowControlFlag byte

const (
	Sendable          FlowControlFlag = 1
	StreamBlocked     FlowControlFlag = 2
	ConnectionBlocked FlowControlFlag = 3
	// will be represent by StreamBlcked * ConnectionBlocked
	BothBlocked FlowControlFlag = 6
)

func (s *StreamFlowController) SendableByOffset(offset uint64, fin bool) FlowControlFlag {
	connSendable := Sendable
	streamSendable := Sendable
	if !s.IsStreamZero && fin {
		connSendable = s.connFC.SendableByOffset(offset)
	}
	if offset <= s.MaxDataLimit {
		streamSendable = Sendable
	}
	return connSendable * streamSendable
}

func (s *StreamFlowController) ReceivableByOffset(offset uint64, fin bool) error {
	if !s.IsStreamZero && fin {
		err := s.connFC.ReceivableByOffset(offset)
		if err != nil {
			return err
		}
	}

	if offset > s.MaxDataLimit {
		return qtype.FlowControlError
	}
	return nil
}

func (s *StreamFlowController) updateLargestReceived(offset uint64) {
	s.largestReceived = offset
}

func (s *StreamFlowController) updateLargestSent(offset uint64) {
	s.largestSent = offset
}

type ConnectionFlowController struct {
	baseFlowController
}

func (c *ConnectionFlowController) SendableByOffset(largestOffset uint64) FlowControlFlag {
	if c.bytesSent+largestOffset <= c.MaxDataLimit {
		return Sendable
	}
	return ConnectionBlocked
}

func (c *ConnectionFlowController) ReceivableByOffset(largestOffset uint64) error {
	if c.bytesReceived+largestOffset > c.MaxDataLimit {
		return qtype.FlowControlReceivedTooMuchData
	}
	return nil
}

func (c *ConnectionFlowController) updateByteSent(largestOffset uint64) {
	c.bytesSent += largestOffset
}
func (c *ConnectionFlowController) updateByteReceived(largestOffset uint64) {
	c.bytesReceived += largestOffset
}
