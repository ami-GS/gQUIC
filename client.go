package quic

import "github.com/ami-GS/gQUIC/utils"

type Client struct {
	Conn                   *Conn
	RecvChan               chan Packet
	LastSentVersion        uint32
	DecidedVersion         uint32 // if not zero, version negotiation was finished
	BufUntilVersionDecided []Packet
	IsServerObj            bool
	CurrentMaxStreamID     uint32
}

func NewClient(isServerObj bool) (*Client, error) {
	return &Client{
		LastSentVersion:    0,
		DecidedVersion:     0,
		RecvChan:           make(chan Packet),
		IsServerObj:        false,
		CurrentMaxStreamID: 0,
	}, nil
}

func (self *Client) ReadLoop() {
	var err error
	for {
		select {
		case p := <-self.RecvChan:
			// This could be implemented by interface?
			if self.IsServerObj {
				err = self.ReadPacketFromClient(p)
			} else {
				err = self.ReadPacketFromServer(p)
			}
			if err != nil {
				panic(err)
			}
		}
	}
}

func (self *Client) ReadPacketFromServer(p Packet) error {
	// called from Client, the packet comes from server
	// process something for connection, then move to process for client
	header := p.GetHeader()
	if self.DecidedVersion != 0 && header.PublicFlags&CONTAIN_QUIC_VERSION != CONTAIN_QUIC_VERSION {
		self.DecidedVersion = self.LastSentVersion
		self.BufUntilVersionDecided = nil
	}
	switch packet := p.(type) {
	case *VersionNegotiationPacket:
		// TODO: choose versions comes from server if acceptable
		self.LastSentVersion = packet.Versions[0]
		for _, p := range self.BufUntilVersionDecided {
			// skip self.Send to re buffer
			err := self.Conn.WritePacket(p)
			if err != nil {
				return err
			}
		}
	case *FramePacket:
		for _, f := range packet.Frames {
			frameType := (*f).GetType()
			switch frameType {
			case AckFrameType, StopWaitingFrameType, //CongestionFeedBackFrameType,
				PingFrameType, ConnectionCloseFrameType, GoAwayFrameType:
				return self.Conn.ReadConnectionLevelFrame((*f))
			case StreamFrameType, WindowUpdateFrameType, BlockedFrameType, RstStreamFrameType:
				sFrame := (*f).(StreamLevelFrame)
				return ReadStreamLevelFrame(self.Conn, sFrame)
			}
		}
	case *PublicResetPacket:
		// Abrubt termination
		return self.Conn.Close()
	}
	return nil
}

func (self *Client) ReadPacketFromClient(p Packet) error {
	// called from Server, the packet comes from client
	// process something for connection, then move to process for client
	header := p.GetHeader()
	if header.PublicFlags&CONTAIN_QUIC_VERSION == CONTAIN_QUIC_VERSION {
		if self.DecidedVersion != 0 {
			// as spec, check version flag. ignore packet if flag is set and version is already decided
			// return nil
		} else {
			// check applicable versions from list
			for _, v := range header.Versions {
				for _, vv := range QUIC_VERSION_LIST {
					if v == vv {
						self.DecidedVersion = vv
						goto VerDecided
					}
				}
			}
		VerDecided:
			if self.DecidedVersion == 0 {
				err := self.Send(NewVersionNegotiationPacket(p.GetConnectionID(), QUIC_VERSION_LIST))
				return err
			}
		}
	}

	switch packet := p.(type) {
	case *VersionNegotiationPacket:
		// emit error?
		// client should not send version negotiatino packet
	case *FramePacket:
		for _, f := range packet.Frames {
			frameType := (*f).GetType()
			switch frameType {
			case AckFrameType, StopWaitingFrameType, //CongestionFeedBackFrameType,
				PingFrameType, ConnectionCloseFrameType, GoAwayFrameType:
				return self.Conn.ReadConnectionLevelFrame((*f))
			case StreamFrameType, WindowUpdateFrameType, BlockedFrameType, RstStreamFrameType:
				sFrame := (*f).(StreamLevelFrame)
				return ReadStreamLevelFrame(self.Conn, sFrame)
			}
		}
	case *PublicResetPacket:
		// Abrubt termination
		return self.Conn.Close()
	}
	return nil
}

// Func name should be same as that of http
func (self *Client) Connect(addPair string) error {
	// if connection is stil alive, then skip
	rAddr, err := utils.ParseAddressPair(addPair)
	if err != nil {
		return err
	}
	conn, err := NewConnection(rAddr)
	if err != nil {
		return err
	}
	self.Conn = conn
	err = self.Conn.Dial()
	if err != nil {
		return err
	}
	p := NewFramePacket(self.Conn.ConnectionID, 1)
	p.PacketHeader.PublicFlags |= CONTAIN_QUIC_VERSION
	p.PacketHeader.Versions = QUIC_VERSION_LIST
	if err != nil {
		return err
	}
	return self.Send(p)
}

func (self *Client) Request() error {
	// should call Connect() from here
	// if connected, then send request
	// if no version flag, FinVersionNegotiation = true
	return nil
}

func (self *Client) Send(p Packet) error {
	// TODO : this would also be implemented by interface
	if self.IsServerObj && self.DecidedVersion == 0 {
		self.BufUntilVersionDecided = append(self.BufUntilVersionDecided, p)
	}

	return self.Conn.WritePacket(p)
}

func (self *Client) FramePacket(frames []*Frame) error {
	// TODO: When is new connectionID created?
	//       and how is packet number decided?
	p := NewFramePacket(0, 0)
	p.Frames = frames
	return self.Conn.WritePacket(p)
}

func (self *Client) PublicResetPacket() {}
