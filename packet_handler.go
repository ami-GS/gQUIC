package quic

type PacketHandler interface {
	handleInitialPacket(p *InitialPacket) error
	handleVersionNegotiationPacket(p *VersionNegotiationPacket) error
	handleRetryPacket(p *RetryPacket) error
	handleHandshakePacket(p *HandshakePacket) error
}

type BasePacketHandler struct{}

func (h *BasePacketHandler) handleInitialPacket(p *InitialPacket) error {
	// log not implemented
	return nil
}

func (h *BasePacketHandler) handleVersionNegotiationPacket(p *VersionNegotiationPacket) error {
	// log not implemented
	return nil
}

func (h *BasePacketHandler) handleRetryPacket(p *RetryPacket) error {
	// log not implemented
	return nil
}

func (h *BasePacketHandler) handleHandshakePacket(p *HandshakePacket) error {
	// log not implemented
	return nil
}
