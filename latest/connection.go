package quiclatest

import "net"

type Connection struct {
	conn       net.PacketConn
	remoteAddr net.Addr
}

func (c *Connection) Write(data []byte) error {
	_, err := c.conn.WriteTo(data, c.remoteAddr)
	return err
}
func (c *Connection) Read(data []byte) (int, net.Addr, error) {
	// the buffer size is decided by session
	return c.conn.ReadFrom(data)
}
func (c *Connection) Close() {
	c.conn.Close()
}
