package quiclatest

import (
	"net"
	"sync"

	qerror "github.com/ami-GS/gQUIC/latest/error"
	"github.com/ami-GS/gQUIC/latest/qtype"
)

type Server struct {
	conn net.PacketConn
	// TODO: replace to SessionStore
	sessions          map[string]*Session //ConnectionID.String():Session
	addrSessions      map[string]*Session //remoteAddr.String():Session, for identifing single connection if zero-len dest ID
	sessionsMutex     *sync.Mutex
	SupportedVersions []qtype.Version
	// TODO: consider here? or in utility? or decide dynamically?
	SessionLimitNum int
	NumHandshake    int
}

func ListenAddr(addr string) (*Server, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	s := &Server{
		conn:              conn,
		sessions:          make(map[string]*Session),
		addrSessions:      make(map[string]*Session),
		sessionsMutex:     new(sync.Mutex),
		SupportedVersions: qtype.SupportedVersions,
		// TODO: experimental
		SessionLimitNum: 1000,
	}
	go s.Serve()
	return s, nil
}

func (s *Server) Serve() error {
	buffer := make([]byte, qtype.MTUIPv4)
	for {
		length, remoteAddr, err := s.conn.ReadFrom(buffer)
		if err != nil {
			s.conn.Close()
			return err
		}
		packets, _, err := ParsePackets(buffer[:length])
		if err != nil {
			// TODO: this type assertion is dangerous
			// TODO: err should have frame info and pass as 1st argument
			_ = s.Close(0, err.(qerror.TransportError))
			return err
		}

		for _, p := range packets {
			err = s.handlePacket(remoteAddr, p)
			if err != nil {
				s.conn.Close()
				return err
			}
		}
	}
}

func (s *Server) Close(fType FrameType, err qerror.TransportError) error {
	wg := &sync.WaitGroup{}
	frame := NewConnectionCloseFrame(fType, err, "error: experimental")
	for _, session := range s.sessions {
		wg.Add(1)
		go func(sess *Session) {
			// this sends connection close frame to peer
			sess.Close(frame)
			wg.Done()
		}(session)
	}
	wg.Wait()
	s.conn.Close()
	// close conn
	return nil
}

func (s *Server) handlePacket(remoteAddr net.Addr, packet Packet) error {
	ph := packet.GetHeader()
	srcID, destID := ph.GetConnectionIDPair()
	lh, longHeaderOK := ph.(*LongHeader)
	// need to check session existence?
	if longHeaderOK && !s.IsVersionSupported(lh.Version) {
		err := s.SendVersionNegotiationPacket(srcID, destID, remoteAddr)
		if err != nil {
		}
		return nil
	}

	var ok bool
	var sess *Session
	if len(destID) != 0 {
		s.sessionsMutex.Lock()
		sess, ok = s.sessions[destID.String()]
		s.sessionsMutex.Unlock()
		if !ok {
			if longHeaderOK && !s.IsAcceptableSession(lh.Version, srcID, destID, remoteAddr) {
				return nil
			}

			// TODO: have to reset Session when Retry Packet sent to client. then thsi can use DestID for packet maching
			sess = NewSession(&Connection{conn: s.conn, remoteAddr: remoteAddr}, destID, srcID, false)
			sess.server = s
			// packet handler for each session on server is now defined in session.go
			sess.packetHandler = sess
			// TODO: be careful to use lh
			if longHeaderOK {
				sess.versionDecided = lh.Version
			} else {
				// error ?
				panic("not a long header")
			}
			go sess.Run()

			// might be deleted after handling packet
			s.sessionsMutex.Lock()
			s.sessions[destID.String()] = sess
			s.addrSessions[remoteAddr.String()] = sess
			s.sessionsMutex.Unlock()
		} else if packet.IsProbePacket() {
			//s.handleMigration()
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

func (s *Server) handleMigration(remoteAddr net.Addr, destID, srcID qtype.ConnectionID) {
	// TODO: have to reset Session when Retry Packet sent to client. then thsi can use DestID for packet maching
	sess := NewSession(&Connection{conn: s.conn, remoteAddr: remoteAddr}, destID, srcID, false)
	sess.server = s
	// packet handler for each session on server is now defined in session.go
	sess.packetHandler = sess
	go sess.Run()

	sess.HandleMigration()

}

func (s *Server) IsVersionSupported(version qtype.Version) bool {
	for _, v := range s.SupportedVersions {
		if v == version {
			return true
		}
	}
	return false
}

func (s *Server) IsAcceptableSession(version qtype.Version, srcID, destID qtype.ConnectionID, remoteAddr net.Addr) bool {
	s.sessionsMutex.Lock()
	sessionNum := len(s.sessions)
	s.sessionsMutex.Unlock()
	if sessionNum >= s.SessionLimitNum {
		p := NewHandshakePacket(version, srcID, destID, qtype.InitialPacketNumber,
			[]Frame{NewConnectionCloseFrame(0, qerror.ServerBusy, "The number of session reached server limit")})
		wire, err := p.GetWire()
		if err != nil {
			//
		}
		_, err = s.conn.WriteTo(wire, remoteAddr)
		return false
	}
	return true
}

func (s *Server) DeleteSessionFromMap(ID qtype.ConnectionID) {
	s.sessionsMutex.Lock()
	defer s.sessionsMutex.Unlock()
	delete(s.sessions, ID.String())
}

func (s *Server) ChangeConnectionID(fromID, toID qtype.ConnectionID) {
	s.sessionsMutex.Lock()
	defer s.sessionsMutex.Unlock()
	session := s.sessions[fromID.String()]
	delete(s.sessions, fromID.String())
	s.sessions[toID.String()] = session
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
