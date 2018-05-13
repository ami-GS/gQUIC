package quiclatest

import (
	"net"

	"github.com/ami-GS/gQUIC/latest/qtype"
)

type SessionStore struct {
	sessions     map[string]*Session   //ConnectionID.String():Session
	addrSessions map[string][]*Session //remoteAddr.String():Session, for identifing single connection if zero-len dest ID
}

func (s SessionStore) GetSession(connID qtype.ConnectionID, remoteAddr net.Addr) (*Session, bool) {
	sess, ok := s.sessions[connID.String()]
	if ok {
		return sess, ok
	}
	sessions, ok := s.addrSessions[remoteAddr.String()]
	if ok && len(sessions) == 1 {
		return sessions[0], ok
	}
	return nil, false
}

func (s *SessionStore) Store(connID qtype.ConnectionID, remoteAddr net.Addr, sess *Session) {
	s.sessions[connID.String()] = sess

	_, ok := s.addrSessions[remoteAddr.String()]
	if !ok {
		// init
		s.addrSessions[remoteAddr.String()] = make([]*Session, 0)
	}
	s.addrSessions[remoteAddr.String()] = append(s.addrSessions[remoteAddr.String()], sess)
}

func deleteElement(s []*Session, i int) []*Session {
	s = append(s[:i], s[i+1:]...)
	n := make([]*Session, len(s))
	copy(n, s)
	return n
}

func (s *SessionStore) Delete(connID qtype.ConnectionID, remoteAddr net.Addr) {
	sess := s.sessions[connID.String()]
	delete(s.sessions, connID.String())

	sessions, ok := s.addrSessions[remoteAddr.String()]
	if ok {
		i := 0
		for ; i < len(sessions); i++ {
			if sessions[i] == sess {
				break
			}
		}
		sessions = deleteElement(sessions, i)
		if len(sessions) == 0 {
			delete(s.addrSessions, remoteAddr.String())
		}
	}
}
