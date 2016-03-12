package quic

type Server struct {
	St      *Transport
	clients []*Client
}

func (self *Server) FramePacket(frames []*Frame) {}

func (self *Server) PublicResetPacket() {}

func (self *Server) VersionNegotiationPacket() {}

func (self *Server) FECPacket() {}

func (self *Server) checkProposedVersion(prppVersion uint32) bool {
	// compare the proposed version to lists
	return true
}
