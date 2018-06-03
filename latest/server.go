package quiclatest

import (
	"net"

	"github.com/ami-GS/gQUIC/latest/qtype"
)

type Server struct {
	conn net.PacketConn
	// TODO: replace to SessionStore
	sessions          map[string]*Session //ConnectionID.String():Session
	addrSessions      map[string]*Session //remoteAddr.String():Session, for identifing single connection if zero-len dest ID
	SupportedVersions []qtype.Version
}

func (s *Server) Serve() error {
	// TODO: set MTU
	buffer := make([]byte, qtype.MTUIPv4)
	data := make([]byte, qtype.MTUIPv4)
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

		err = s.handlePacket(remoteAddr, packet)
		if err != nil {
			s.conn.Close()
			return err
		}
	}
}

func (s *Server) handlePacket(remoteAddr net.Addr, packet Packet) error {
	ph := packet.GetHeader()
	srcID, destID := ph.GetConnectionIDPair()
	lh, ok := ph.(LongHeader)
	// need to check session existence?
	if ok && !s.IsVersionSupported(lh.Version) {
		err := s.SendVersionNegotiationPacket(srcID, destID, remoteAddr)
		if err != nil {
		}
		return nil
	}

	var sess *Session
	if len(destID) != 0 {
		sess, ok = s.sessions[destID.String()]
		if !ok {
			sess = NewSession(&Connection{conn: s.conn, remoteAddr: remoteAddr}, destID, srcID)
			// packet handler for each session on server is now defined in session.go
			sess.packetHandler = sess
			// TODO: be careful to use lh
			sess.versionDecided = lh.Version

			// might be deleted after handling packet
			s.sessions[destID.String()] = sess
			s.addrSessions[remoteAddr.String()] = sess
		}
	} else {
		sess, ok = s.addrSessions[remoteAddr.String()]
		if !ok {
			// drop packet if no corresponding connection
			return nil
		}
	}
	sess.HandlePacket(packet)
	return nil
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
