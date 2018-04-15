package quic

import (
	"time"

	"github.com/ami-GS/gQUIC/utils"
)

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
		IsServerObj:        isServerObj,
		CurrentMaxStreamID: 0,
	}, nil
}

func (self *Client) Loop() {
	go self.ReadLoop()
	for {
		p, _, _, err := self.Conn.Recv()
		if err != nil {
			panic(err)
		}
		self.RecvChan <- p
	}
}

func (self *Client) ReadLoop() {
	var err error
	var hasAck bool
	for {
		select {
		case p := <-self.RecvChan:
			// This could be implemented by interface?
			// TODO : ack should use buffer to maximize efficiency
			// Currently just send ack for each packet
			if self.IsServerObj {
				hasAck, err = self.ReadPacketFromClient(p)
			} else {
				hasAck, err = self.ReadPacketFromServer(p)
			}
			if !hasAck {
				packetNow := time.Now()
				num := p.GetHeader().PacketNumber
				pkt := NewFramePacket(self.Conn.ConnectionID, self.Conn.PacketIdx, []Frame{
					NewAckFrame(num, uint16(time.Now().Sub(packetNow)/time.Millisecond), []uint64{num}, []Timestamp{
						Timestamp{
							DeltaLargestAcked:     byte(num - num), // packet number = largest acked - DeltaLargestAcked
							TimeSinceLargestAcked: uint32(time.Now().Sub(self.Conn.TimeSpawn)),
						},
					},
					)})
				err = self.Send(pkt)
			}
			if err != nil {
				panic(err)
			}
		}
	}
}

func (self *Client) ReadPacketFromServer(p Packet) (bool, error) {
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
			err := self.Conn.WritePacket(p, self.IsServerObj)
			if err != nil {
				return false, err
			}
		}
	case *FramePacket:
		for _, f := range packet.Frames {
			frameType := f.GetType()
			switch frameType {
			case AckFrameType, StopWaitingFrameType, //CongestionFeedBackFrameType,
				PingFrameType, ConnectionCloseFrameType, GoAwayFrameType:
				return self.Conn.ReadConnectionLevelFrame(f)
			case StreamFrameType, WindowUpdateFrameType, BlockedFrameType, RstStreamFrameType:
				sFrame := f.(StreamLevelFrame)
				return ReadStreamLevelFrame(self.Conn, sFrame)
			}
		}
	case *PublicResetPacket:
		// Abrubt termination
		return false, self.Conn.Close()
	}

	return false, nil
}

func (self *Client) ReadPacketFromClient(p Packet) (bool, error) {
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
				return false, err
			}
		}
	}

	switch packet := p.(type) {
	case *VersionNegotiationPacket:
		// emit error?
		// client should not send version negotiatino packet
	case *FramePacket:
		for _, f := range packet.Frames {
			frameType := f.GetType()
			switch frameType {
			case AckFrameType, StopWaitingFrameType, //CongestionFeedBackFrameType,
				PingFrameType, ConnectionCloseFrameType, GoAwayFrameType:
				return self.Conn.ReadConnectionLevelFrame(f)
			case StreamFrameType, WindowUpdateFrameType, BlockedFrameType, RstStreamFrameType:
				sFrame := f.(StreamLevelFrame)
				return ReadStreamLevelFrame(self.Conn, sFrame)
			case PaddingFrameType:
			}
		}
	case *PublicResetPacket:
		// Abrubt termination
		return false, self.Conn.Close()
	}
	return false, nil
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
	self.Conn.RemoteAddr = rAddr
	err = self.Conn.Dial()
	if err != nil {
		return err
	}
	p := NewFramePacket(self.Conn.ConnectionID, 1, nil)
	p.PacketHeader.PublicFlags |= CONTAIN_QUIC_VERSION
	p.PacketHeader.Versions = QUIC_VERSION_LIST
	if err != nil {
		return err
	}
	go self.Loop()
	return self.Send(p)
}

func (self *Client) Request() error {
	// should call Connect() from here
	// if connected, then send request
	// if no version flag, FinVersionNegotiation = true
	return nil
}

func (self *Client) SendFramePacket(frames []Frame) error {
	p := NewFramePacket(self.Conn.ConnectionID, self.Conn.PacketIdx, frames)
	err := self.Send(p)
	return err
}

func (self *Client) Ping() {
	f := []Frame{
		NewPingFrame(),
	}
	self.SendFramePacket(f)
}

func (self *Client) PublicResetPacket() {

}

func (self *Client) Send(p Packet) error {
	// TODO : this would also be implemented by interface
	if self.IsServerObj && self.DecidedVersion == 0 {
		self.BufUntilVersionDecided = append(self.BufUntilVersionDecided, p)
	}
	return self.Conn.WritePacket(p, self.IsServerObj)
}
