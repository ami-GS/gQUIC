package quiclatest

import "net"

type Server struct {
	conn     net.PacketConn
	sessions map[string]*Session //ConnectionID.String():Session
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
		srcID, destID := packet.GetHeader().GetConnectionIDPair()
		sess, ok := s.sessions[srcID.String()]
		if !ok {
			sess = NewSession(&Connection{conn: s.conn, remoteAddr: remoteAddr}, destID, srcID)
		}
		sess.ReceivePacket(packet)
	}
}
