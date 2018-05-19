package quiclatest

import (
	"net"

	"github.com/ami-GS/gQUIC/latest/qtype"
)

type Client struct {
	remoteAddr        net.Addr
	session           *Session
	versionOffer      qtype.Version
	versionDecided    qtype.Version
	versionNegotiated bool
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
		session:           NewSession(&Connection{conn: udpConn, remoteAddr: remoteAddr}, srcConnID, destConnID),
		versionOffer:      qtype.VersionZero,
		versionDecided:    qtype.VersionPlaceholder,
		versionNegotiated: false,
	}
	go cli.run()
	return cli, nil
}

func (c *Client) run() {
	buffer := make([]byte, 1500)
	data := make([]byte, 1500)
	for {
		length, _, err := c.session.conn.Read(buffer)
		if err != nil {
			//
		}
		copy(data[:length], buffer[:length])

		packet, _, err := ParsePacket(data)
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
	switch packet := p.(type) {
	case VersionNegotiationPacket:
		c.handleVersionNegotiationPacket(&packet)
	case RetryPacket:
		c.versionNegotiated = true
		c.handleRetryPacket(&packet)
	case HandshakePacket:
		c.versionNegotiated = true
		c.handleHandshakePacket(&packet)
	default:
		return nil
	}
	return nil
}

func (c *Client) handleVersionNegotiationPacket(packet *VersionNegotiationPacket) {
	// TODO: priority queue?
	for _, version := range packet.SupportedVersions {
		for _, supportedVersion := range qtype.SupportedVersions {
			if version == supportedVersion {
				c.versionDecided = version
				goto FOUND_VERSION
			}
		}
	}
FOUND_VERSION:
	// Do something
}

func (c *Client) handleRetryPacket(packet *RetryPacket) {
	ph := packet.GetHeader()
	srcConnID, _ := ph.GetConnectionIDPair()
	c.session.DestConnID = srcConnID

	// RetryPacket MUST contain at least two frames
	// one is STREAM frame with ID of 0 and ofsset of 0
	c.session.HandleFrames(packet.GetFrames())
}

func (c *Client) handleHandshakePacket(packet *HandshakePacket) {

}
