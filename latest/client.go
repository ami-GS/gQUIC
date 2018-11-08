package quiclatest

import (
	"bytes"
	"net"

	qerror "github.com/ami-GS/gQUIC/latest/error"
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
		f = NewConnectionCloseFrame(0, qerror.NoError, "Close request from client")
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

func (c *Client) readTokenInfo() (*qtype.TokenInfo, bool) {
	return nil, false
}

func (c *Client) ReadUsableToken() []byte {
	// TODO: not fully implemented
	// 1. whether client has token? true -> 2.
	if tknInfo, exists := c.readTokenInfo(); exists {
		// 2. check local IP and network interface, is it different from that of used last time? true -> return last token.
		localAddr := c.session.conn.conn.LocalAddr().(*net.UDPAddr)
		if tknInfo.Addr != localAddr.String() {
			return nil
		}

		ifaces, err := net.Interfaces()
		if err != nil {
			panic(err)
		}
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil {
				panic(err)
			}

			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					continue
				case *net.IPAddr:
					if localAddr.String() == v.IP.String() {
						if tknInfo.Iface == iface.Name {
							return tknInfo.Raw
						}
					}
				}
			}
		}

	}
	// For now, return nil
	return nil
}

func (c *Client) Connect() {
	// version negotiation
	// wait response

	token := c.ReadUsableToken()

	// first initial packet
	destID, _ := qtype.NewConnectionID(nil)
	c.session.sendPacketChan <- //NewCoalescingPacket([]Packet{
	NewInitialPacket(c.versionOffer, destID, destID, token, c.session.LastInitialPN.Increase(),
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
	if p.IsProbePacket() {
		// TODO: handle error or ignore
	}

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
		c.session.LastInitialPN.Increase(),
		[]Frame{NewCryptoFrame(0, []byte("second cryptographic handshake message for answering VersionNegotiation Packet"))})
	return nil
}

func (c *Client) handleRetryPacket(packet *RetryPacket) error {
	// send second initial packet

	// The client retains the state of its cryptographic handshake, but discards all transport state.
	//c.session.DestConnID, _ = packet.GetHeader().GetConnectionIDPair()
	rcvSrcConnID, _ := packet.GetHeader().GetConnectionIDPair()

	if !bytes.Equal(packet.OriginalDestConnID, c.session.DestConnID) {
		/*
			Clients MUST discard Retry packets that contain an Original
			Destination Connection ID field that does not match the Destination
			Connection ID from its Initial packet.
		*/
		panic("original DestinationID mismatch")
		return nil
	}

	c.session.DestConnID = rcvSrcConnID
	c.session.RetryTokenReceived = packet.RetryToken

	// try again with new transport, but MUST remember the results of any version negotiation that occurred
	pn := packet.GetPacketNumber()
	c.session.sendPacketChan <- NewInitialPacket(c.session.versionDecided, rcvSrcConnID, c.session.SrcConnID,
		packet.RetryToken, pn.Increase(),
		[]Frame{NewCryptoFrame(qtype.QuicInt(len("first cryptographic handshake message (ClientHello)")), []byte("second cryptographic handshake message"))})
	return nil
}

func (c *Client) handleHandshakePacket(packet *HandshakePacket) error {
	return nil
}

func (c *Client) handleInitialPacket(packet *InitialPacket) error {
	pn := packet.GetPacketNumber()
	if packet.TokenLen != 0 {
		c.session.sendPacketChan <- NewProtectedPacket0RTT(c.session.versionDecided, c.session.DestConnID, c.session.SrcConnID, pn.Increase(), []Frame{NewConnectionCloseFrame(0, qerror.ProtocolViolation, "client receives initial packet with Non-zero token length")})
	}
	return nil
}
