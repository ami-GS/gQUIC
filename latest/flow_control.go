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

func (s *StreamFlowController) SendableByOffset(offset uint64, fin bool) bool {
	sendable := true
	if !s.IsStreamZero && fin {
		sendable = s.connFC.SendableByOffset(offset)
	}
	return sendable && offset <= s.MaxDataLimit
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

func (c *ConnectionFlowController) SendableByOffset(largestOffset uint64) bool {
	return c.bytesSent+largestOffset <= c.MaxDataLimit
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
