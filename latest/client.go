package quiclatest

import (
	"net"

	"github.com/ami-GS/gQUIC/latest/qtype"
)

type Client struct {
	*BasePacketHandler

	remoteAddr        net.Addr
	session           *Session
	versionOffer      qtype.Version
	versionNegotiated bool
}

func (s *Client) Send(data []byte) (int, error) {
	return s.session.Write(data)
}

func (s *Client) Close() {
	s.close(nil)
}

func (s *Client) close(f *ConnectionCloseFrame) {
	if f == nil {
		f = NewConnectionCloseFrame(qtype.NoError, "Close request from client")
	}
	s.session.Close(f)
}

func DialAddr(addr string) (*Client, error) {
	remoteAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	srcAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	udpConn, err := net.ListenUDP("udp", srcAddr)

	srcConnID, err := qtype.NewConnectionID(nil)
	if err != nil {
		return nil, err
	}
	// have same ID until getting Retry Packet
	destConnID := srcConnID

	cli := &Client{
		remoteAddr:        remoteAddr,
		session:           NewSession(&Connection{conn: udpConn, remoteAddr: remoteAddr}, srcConnID, destConnID, true),
		versionOffer:      qtype.VersionQuicTLS,
		versionNegotiated: false,
	}
	cli.session.packetHandler = cli
	go cli.run()
	return cli, nil
}

func (c *Client) Connect() {
	// version negotiation
	// wait response

	// first initial packet
	destID, _ := qtype.NewConnectionID(nil)
	streamFrame := NewStreamFrame(0, 0, true, true, false, []byte("Initial Packet with ClientHello"))
	c.session.sendPacketChan <- NewInitialPacket(c.versionOffer, destID, destID, c.session.LastPacketNumber, streamFrame)
	c.session.DestConnID = destID
	c.session.SrcConnID = destID

	//
}

func (c *Client) run() {
	go c.session.Run()
	buffer := make([]byte, qtype.MTUIPv4)
	for {
		length, _, err := c.session.conn.Read(buffer)
		if err != nil {
			//
		}
		packet, _, err := ParsePacket(buffer[:length])
		if err != nil {
			//
		}
		/*
			// TODO: Retry Packet ?
						srcConnID, destConnID := packet.GetHeader().GetConnectionIDPair()
						if len(destConnID) != 0 && !destConnID.Equal(c.session.DestConnID) {
							// MAY discard
						}
		*/
		c.handlePacket(packet)
	}
}

func (c *Client) handlePacket(p Packet) error {
	if _, ok := p.(*VersionNegotiationPacket); !ok && c.versionNegotiated == false {
		c.versionNegotiated = true
		c.session.versionDecided = c.versionOffer
	}

	return c.session.HandlePacket(p)
}

func (c *Client) handleVersionNegotiationPacket(packet *VersionNegotiationPacket) error {
	// TODO: shoulsd be written in session?
	if c.versionNegotiated {
		// Once a client receives a packet from the server which is not a Version Negotiation
		// packet, it MUST discard other Version Negotiation packets on the same connection.
		return nil
	}
	if !c.session.SrcConnID.Equal(packet.DestConnID) || !c.session.DestConnID.Equal(packet.SrcConnID) {
		// If this check fails, the packet MUST be discarded.
		return nil
	}

	// TODO: priority queue?
	found := false
	versionTBD := qtype.Version(0)
	for _, version := range packet.SupportedVersions {
		if version == c.versionOffer {
			// MUST ignore a Version Negotiation packet that lists the client's chosen version.
			return nil
		}

		if !found {
			for _, supportedVersion := range qtype.SupportedVersions {
				if version == supportedVersion {
					found = true
					versionTBD = version
				}
			}
		}
	}
	c.versionOffer = versionTBD
	// WIP
	streamFrame := NewStreamFrame(0, 0, true, true, false, []byte("second Initial Packet for anwering VersionNegotiation Packet"))
	c.session.sendPacketChan <- NewInitialPacket(c.versionOffer, c.session.DestConnID, c.session.SrcConnID, c.session.LastPacketNumber.Increase(), streamFrame)
	return nil
}

func (c *Client) handleRetryPacket(packet *RetryPacket) error {
	// send second initial packet

	// RetryPacket MUST contain at least two frames (Ack and Stream)
	frames := packet.GetFrames()
	requiredPacket := 0
	for _, frame := range frames {
		if frame.GetType() == AckFrameType {
			// TODO: check largest acked is same as that of previous initial packet
			requiredPacket++
		} else if frame.GetType()&StreamFrameType == StreamFrameType {
			stFrame := frame.(*StreamFrame)
			if stFrame.Offset == 0 && stFrame.GetStreamID() == 0 {
				requiredPacket++
			}
		}
	}
	if requiredPacket < 2 {
		return qtype.ProtocolViolation
	}

	// The client retains the state of its cryptographic handshake, but discards all transport state.
	c.session.DestConnID, _ = packet.GetHeader().GetConnectionIDPair()
	c.session.SrcConnID, _ = qtype.NewConnectionID(nil)

	// try again with new transport, but MUST remember the results of any version negotiation that occurred
	pn := packet.GetPacketNumber()

	c.session.sendPacketChan <- NewInitialPacket(c.session.versionDecided, c.session.DestConnID, c.session.SrcConnID, pn.Increase(),
		NewStreamFrame(0, 0, true, true, false, []byte("Second Initial Packet response for Retry Packet")))
	return nil
}

func (c *Client) handleHandshakePacket(packet *HandshakePacket) error {
	return nil
}
