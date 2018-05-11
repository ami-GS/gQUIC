package quiclatest

import (
	"net"

	"github.com/ami-GS/gQUIC/latest/qtype"
)

type Server struct {
	conn              net.PacketConn
	sessions          map[string]*Session //ConnectionID.String():Session
	SupportedVersions []qtype.Version
}

func (s *Server) Serve() error {
	// TODO: set MTU
	buffer := make([]byte, 1500)
	data := make([]byte, 1500)
	for {
		length, remoteAddr, err := s.conn.ReadFrom(buffer)
		if err != nil {
			s.conn.Close()
			return err
		}
		// TODO:copy should be slow
		copy(data[:length], buffer[:length])

		packet, _, err := ParsePacket(data)
		if err != nil {
			s.conn.Close()
			return err
		}
		ph := packet.GetHeader()
		srcID, destID := ph.GetConnectionIDPair()
		lh, ok := ph.(LongHeader)
		// need to check session existence?
		if ok && !s.IsVersionSupported(lh.Version) {
			err := s.SendVersionNegotiationPacket(srcID, destID, remoteAddr)
			if err != nil {
			}
			continue
		}

		sess, ok := s.sessions[destID.String()]
		if !ok {
			sess = NewSession(&Connection{conn: s.conn, remoteAddr: remoteAddr}, destID, srcID)
			// might be deleted after handling packet
			s.sessions[destID.String()] = sess
		}
		sess.HandlePacket(packet)
	}
}

func (s *Server) IsVersionSupported(version qtype.Version) bool {
	for _, v := range s.SupportedVersions {
		if v == version {
			return true
		}
	}
	return false
}

func (s *Server) SendVersionNegotiationPacket(srcID, destID qtype.ConnectionID, remoteAddr net.Addr) error {
	p := NewVersionNegotiationPacket(srcID, destID, s.SupportedVersions)
	wire, err := p.GetWire()
	if err != nil {
		//
	}
	_, err = s.conn.WriteTo(wire, remoteAddr)
	return err
}
