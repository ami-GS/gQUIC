package quiclatest

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

func (s *StreamFlowController) SendableBySize(largestOffset uint64) bool {
	return largestOffset <= s.MaxDataLimit
}

func (s *StreamFlowController) updateLargestReceived(offset uint64) {
	s.largestReceived = offset
	if !s.IsStreamZero {
		s.connFC.updateByteReceived(offset) // TODO: not correct
	}
}

func (s *StreamFlowController) updateLargestSent(offset uint64) {
	s.largestSent = offset
	if !s.IsStreamZero {
		s.connFC.updateByteSent(offset) // TODO: not correct
	}
}

type ConnectionFlowController struct {
	baseFlowController
}

func (c *ConnectionFlowController) updateByteSent(bytes uint64) {
	c.bytesSent += bytes
}
func (c *ConnectionFlowController) updateByteReceived(bytes uint64) {
	c.bytesReceived += bytes
}
