package tn3270e

import (
	"net"
	"time"
)

// Raw telnet command bytes. go3270 defines its own copies of these as
// unexported constants, so we can't reuse them from outside the package.
const (
	iacByte  = 255
	willByte = 251
	wontByte = 252
	doByte   = 253
	dontByte = 254

	tn3270EOption = 40 // RFC 2355; go3270 only speaks plain TN3270.
)

// prefixConn replays a buffered prefix of already-read bytes before falling
// through to Conn's own Read, so bytes consumed while peeking at a client's
// unsolicited option offers aren't lost to whatever reads the connection
// next.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// drainAvailable reads whatever bytes a client sends within initial of the
// call, then keeps coalescing any immediately-following bytes (allowing up
// to coalesce of silence between reads) until the client stops sending.
// Returns an empty slice, after waiting initial, for a client that doesn't
// speak first.
func drainAvailable(conn net.Conn, initial, coalesce time.Duration) []byte {
	tmp := make([]byte, 64)

	_ = conn.SetReadDeadline(time.Now().Add(initial))
	n, err := conn.Read(tmp)
	buf := append([]byte(nil), tmp[:n]...)

	for err == nil {
		_ = conn.SetReadDeadline(time.Now().Add(coalesce))
		n, err = conn.Read(tmp)
		buf = append(buf, tmp[:n]...)
	}

	_ = conn.SetReadDeadline(time.Time{})
	return buf
}
