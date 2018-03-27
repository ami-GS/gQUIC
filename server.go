package quic

import (
	"github.com/ami-GS/gQUIC/utils"
)

type Server struct {
	St              *Transport
	Clients         map[uint64]*Client
	SupportVersions []uint32
}

func NewServer() (*Server, error) {
	st, err := NewTransport("cert", "key")
	if err != nil {
		return nil, err
	}
	return &Server{
		St:      st,
		Clients: make(map[uint64]*Client),
	}, nil
}

func (self *Server) ListenAndServe(addPair string) error {
	udpAddr, err := utils.ParseAddressPair(addPair)
	if err != nil {
		return err
	}

	err = self.St.Listen(udpAddr)
	if err != nil {
		return err
	}

	for {
		p, _, rAddr, err := self.St.Recv()
		if err != nil {
			break
		}
		client, ok := self.Clients[p.GetConnectionID()]
		if ok {
			client.RecvChan <- p
		} else {
			client, err = NewClient(true) // true stands for server side object
			if err != nil {
				break
			}
			client.Conn, err = NewConnection(rAddr)
			client.Conn.Transport = self.St
			client.Conn.ConnectionID = p.GetConnectionID()
			if err != nil {
				break
			}
			self.Clients[p.GetConnectionID()] = client
			go client.ReadLoop()
			client.RecvChan <- p
		}
	}

	return err
}

func (self *Server) FramePacket(frames []*Frame) {}

func (self *Server) PublicResetPacket() {}

func (self *Server) VersionNegotiationPacket() {}

func (self *Server) checkProposedVersion(prppVersion uint32) bool {
	// compare the proposed version to lists
	return true
}
