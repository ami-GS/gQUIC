package quiclatest

import (
	"fmt"
	"sync"

	"github.com/ami-GS/gQUIC/latest/qtype"
)

type baseFlowController struct {
	bytesSent       qtype.QuicInt
	bytesReceived   qtype.QuicInt
	largestSent     qtype.QuicInt
	largestReceived qtype.QuicInt

	limitMutex   sync.Mutex
	MaxDataLimit qtype.QuicInt
}

func (f *baseFlowController) String() string {
	return fmt.Sprintf("sent:%d, recvd:%d, largestSent:%d, largestRcvd:%d\nMaxDataLimit:%d", f.bytesSent, f.bytesReceived, f.largestSent, f.largestReceived, f.MaxDataLimit)
}

func (f *baseFlowController) maybeUpdateMaxDataLimit(newLimit qtype.QuicInt) bool {
	f.limitMutex.Lock()
	defer f.limitMutex.Unlock()
	if f.MaxDataLimit < newLimit {
		f.MaxDataLimit = newLimit
		return true
	}
	return false
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

func (s *StreamFlowController) SendableByOffset(offset qtype.QuicInt, fin bool) FlowControlFlag {
	connSendable := Sendable
	streamSendable := Sendable
	if !s.IsStreamZero && fin {
		connSendable = s.connFC.SendableByOffset(offset)
	}
	// TODO: stream 0 can exceed the limit until handshake is finished
	if offset > s.MaxDataLimit {
		streamSendable = StreamBlocked
	}
	return connSendable * streamSendable
}

func (s *StreamFlowController) ReceivableByOffset(offset qtype.QuicInt, fin bool) error {
	if !s.IsStreamZero && fin {
		err := s.connFC.ReceivableByOffset(offset)
		if err != nil {
			return err
		}
	}

	// TODO: stream 0 can exceed the limit until handshake is finished
	if offset > s.MaxDataLimit {
		return qtype.FlowControlError
	}
	return nil
}

func (s *StreamFlowController) updateLargestReceived(offset qtype.QuicInt) {
	s.largestReceived = offset
}

func (s *StreamFlowController) updateLargestSent(offset qtype.QuicInt) {
	s.largestSent = offset
}

type ConnectionFlowController struct {
	baseFlowController
}

func (c *ConnectionFlowController) SendableByOffset(largestOffset qtype.QuicInt) FlowControlFlag {
	if c.bytesSent+largestOffset <= c.MaxDataLimit {
		return Sendable
	}
	return ConnectionBlocked
}

func (c *ConnectionFlowController) ReceivableByOffset(largestOffset qtype.QuicInt) error {
	if c.bytesReceived+largestOffset > c.MaxDataLimit {
		return qtype.FlowControlReceivedTooMuchData
	}
	return nil
}

func (c *ConnectionFlowController) updateByteSent(largestOffset qtype.QuicInt) {
	c.bytesSent += largestOffset
}
func (c *ConnectionFlowController) updateByteReceived(largestOffset qtype.QuicInt) {
	c.bytesReceived += largestOffset
}
