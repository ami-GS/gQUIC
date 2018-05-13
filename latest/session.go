package quiclatest

import "github.com/ami-GS/gQUIC/latest/qtype"

type Session struct {
	// tls config
	// connection
	DestConnID      qtype.ConnectionID
	SrcConnID       qtype.ConnectionID
	DoneHandShake   bool
	conn            *Connection
	recvPacketChann chan Packet
	streamManager   *StreamManager
}

func NewSession(conn *Connection, dstConnID, srcConnID qtype.ConnectionID) *Session {
	sess := &Session{
		DestConnID:      dstConnID,
		SrcConnID:       srcConnID,
		conn:            conn,
		recvPacketChann: make(chan Packet),
	}
	sess.streamManager = &StreamManager{
		streamMap: make(map[uint64]Stream),
		sess:      sess,
	}
	return sess

}

func (s *Session) SendPacket(packet Packet) error {
	wire, err := packet.GetWire()
	if err != nil {
		return err
	}
	return s.conn.Write(wire)
}
func (s *Session) RecvPacketLoop() {
	for {
		select {
		case p := <-s.recvPacketChann:
			// TODO: parallel?
			s.ReceivePacket(p)
		default:
		}
	}
}

func (s *Session) ReceivePacket(p Packet) {
	//TODO: apply packets
}
