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

func (c *Client) Ping() {
	c.session.ping()
}

func (s *Client) Send(data []byte) (int, error) {
	return s.session.Write(data)
}

func (s *Client) Close() {
	s.close(nil)
}

func (s *Client) close(f *ConnectionCloseFrame) {
	if f == nil {
		f = NewConnectionCloseFrame(0, qtype.NoError, "Close request from client")
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
		versionOffer:      qtype.VersionUnsupportedTest,
		versionNegotiated: false,
	}
	cli.session.packetHandler = cli
	go cli.run()
	cli.Connect()

	return cli, nil
}

func (c *Client) Connect() {
	// version negotiation
	// wait response

	// first initial packet
	destID, _ := qtype.NewConnectionID(nil)
	c.session.sendPacketChan <- //NewCoalescingPacket([]Packet{
	NewInitialPacket(c.versionOffer, destID, destID, nil, c.session.LastPacketNumber,
		[]Frame{NewCryptoFrame(0, []byte("first cryptographic handshake message (ClientHello)"))})
	//NewProtectedPacket0RTT(c.versionOffer, destID, destID, c.session.LastPacketNumber, []Frame{NewStreamFrame(0, 0, true, true, false, []byte("0-RTT[0]: STREAM[0, ...]"))}),
	//})
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
			panic(err)
		}
		packets, _, err := ParsePackets(buffer[:length])
		if err != nil {
			panic(err)
		}

		for _, p := range packets {
			err = c.handlePacket(p)
			if err != nil {
				panic(err)
			}
		}

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

	c.session.sendPacketChan <- NewInitialPacket(c.versionOffer, c.session.DestConnID, c.session.SrcConnID, nil,
		c.session.LastPacketNumber,
		[]Frame{NewCryptoFrame(0, []byte("second cryptographic handshake message for answering VersionNegotiation Packet"))})
	return nil
}

func (c *Client) handleRetryPacket(packet *RetryPacket) error {
	// send second initial packet

	// The client retains the state of its cryptographic handshake, but discards all transport state.
	c.session.DestConnID, _ = packet.GetHeader().GetConnectionIDPair()
	c.session.SrcConnID, _ = qtype.NewConnectionID(nil)

	// try again with new transport, but MUST remember the results of any version negotiation that occurred
	pn := packet.GetPacketNumber()
	c.session.sendPacketChan <- NewInitialPacket(c.session.versionDecided, c.session.DestConnID, c.session.SrcConnID,
		packet.RetryToken, pn.Increase(),
		[]Frame{NewCryptoFrame(qtype.QuicInt(len("first cryptographic handshake message (ClientHello)")), []byte("second cryptographic handshake message"))})
	return nil
}

func (c *Client) handleHandshakePacket(packet *HandshakePacket) error {
	return nil
}
