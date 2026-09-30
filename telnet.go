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
	eorByte  = 239

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

// tn3270eReplyTimeout bounds how long readTN3270EReply waits for the client
// to answer DO TN3270E. It has to comfortably exceed a WAN round trip: a
// reply that arrives after we've given up lands in the middle of
// go3270.NegotiateTelnet's own negotiation and breaks it.
const tn3270eReplyTimeout = 3 * time.Second

// readTN3270EReply reads until the client has said something about telnet
// option 40 (WILL, WONT, DO or DONT), or tn3270eReplyTimeout passes, then
// picks up anything bundled right behind it (e.g. dx3270's early
// DEVICE-TYPE REQUEST). Clients that don't speak TN3270E normally refuse
// it straight away, so only a client that ignores the DO entirely waits
// out the timeout.
func readTN3270EReply(conn net.Conn) []byte {
	var buf []byte
	tmp := make([]byte, 64)
	deadline := time.Now().Add(tn3270eReplyTimeout)
	for !hasOptionReply(buf, tn3270EOption) {
		_ = conn.SetReadDeadline(deadline)
		n, err := conn.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			_ = conn.SetReadDeadline(time.Time{})
			return buf
		}
	}
	return append(buf, drainAvailable(conn, 20*time.Millisecond, 20*time.Millisecond)...)
}

// hasOptionReply reports whether buf contains IAC WILL/WONT/DO/DONT opt.
func hasOptionReply(buf []byte, opt byte) bool {
	for i := 0; i+2 < len(buf); i++ {
		if buf[i] == iacByte && buf[i+2] == opt {
			switch buf[i+1] {
			case willByte, wontByte, doByte, dontByte:
				return true
			}
		}
	}
	return false
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
