package tn3270e

import (
	"errors"
	"net"
	"time"
)

// coalescingConnDeadline bounds how long coalescingConn waits for more bytes
// that have already started arriving, after an initial short read. It's not
// a network round-trip budget -- it only needs to span the gap between two
// TCP segments/writes belonging to the same logical message, which a client
// on the other end of even a slow WAN link will close in well under this.
const coalescingConnDeadline = 200 * time.Millisecond

// coalescingConn wraps a net.Conn so that a single Read call keeps reading
// until either the caller's buffer is full or no more data arrives within
// coalescingConnDeadline.
//
// go3270's telnet option negotiation (NegotiateTelnet/getTerminalType/
// checkOptionResponse) does one-shot conn.Read(buf) calls and assumes the
// whole logical telnet message (e.g. a client's terminal-type reply) arrives
// in a single Read. That's not guaranteed by TCP: some clients (observed
// with dx3270) write their negotiation response in a way that the kernel
// delivers across more than one Read, which the library then rejects as a
// malformed/short response and aborts negotiation. Coalescing reads here
// papers over that without modifying go3270.
//
// Coalescing needs short read deadlines of its own, so coalescingConn
// remembers the read deadline its caller last set and puts it back
// afterwards, instead of clearing it. It also enforces ceiling, if set: no
// read or write deadline, including "none", is ever later than that.
// Negotiate uses it to bound the whole negotiation, since go3270 clears
// read deadlines as it goes.
type coalescingConn struct {
	net.Conn
	deadline      time.Time // read deadline the caller last set
	writeDeadline time.Time // write deadline the caller last set
	ceiling       time.Time // latest deadline allowed; zero for no limit
}

func (c *coalescingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil || n == 0 || n >= len(p) {
		return n, err
	}

	var finalErr error
	for n < len(p) {
		wait := earliest(time.Now().Add(coalescingConnDeadline), c.effectiveDeadline())
		if err := c.Conn.SetReadDeadline(wait); err != nil {
			break
		}
		more, rerr := c.Conn.Read(p[n:])
		n += more
		if rerr != nil {
			// A timeout just means no more data has arrived yet -- treat the
			// coalesced read as done. Any other error is real and must be
			// reported once we stop coalescing.
			if ne, ok := rerr.(net.Error); !ok || !ne.Timeout() {
				finalErr = rerr
			}
			break
		}
	}
	_ = c.Conn.SetReadDeadline(c.effectiveDeadline())

	return n, finalErr
}

func (c *coalescingConn) SetReadDeadline(t time.Time) error {
	c.deadline = t
	return c.Conn.SetReadDeadline(c.effectiveDeadline())
}

func (c *coalescingConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return c.Conn.SetWriteDeadline(earliest(t, c.ceiling))
}

func (c *coalescingConn) SetDeadline(t time.Time) error {
	if err := c.SetWriteDeadline(t); err != nil {
		return err
	}
	return c.SetReadDeadline(t)
}

// setCeiling sets the latest deadline allowed (zero for no limit).
func (c *coalescingConn) setCeiling(t time.Time) error {
	c.ceiling = t
	if err := c.Conn.SetWriteDeadline(earliest(c.writeDeadline, t)); err != nil {
		return err
	}
	return c.Conn.SetReadDeadline(c.effectiveDeadline())
}

func (c *coalescingConn) effectiveDeadline() time.Time {
	return earliest(c.deadline, c.ceiling)
}

// earliest returns the earlier of a and b, where zero means no deadline.
func earliest(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

// MaxRecordSize is the most bytes a client may send in one inbound record:
// everything up to the IAC EOR that ends it, or, before the first one,
// everything since the connection opened.
//
// go3270 itself only gets field-mode Read Modified replies (AID, cursor
// address, then an SBA order and the data of each modified field). On the
// largest screen go3270 allows (under 16384 positions) those top out
// around 57 KB. The extra room is for a server that sends Read Buffer: a
// reply with typical extended attributes (color and highlighting on every
// character, a few attribute pairs per field) runs about 8 bytes a
// position, or 131 KB at the largest screen size. Even the pathological
// worst, every attribute on every position at about 18 bytes a position,
// is 295 KB there.
const MaxRecordSize = 512 * 1024

// ErrRecordTooLarge is returned by every Read on a connection whose client
// has sent a record longer than MaxRecordSize.
var ErrRecordTooLarge = errors.New("tn3270e: client sent a record over MaxRecordSize bytes")

// limitConn fails reads once the client sends a record longer than max.
//
// go3270's readResponse keeps collecting field data until the client sends
// IAC EOR, and its negotiation and our own keep reading as long as the
// client keeps sending, so without this a client can make the server
// buffer as much as it likes. Once tripped, every later Read fails too:
// the connection is no longer in a state anything can make sense of.
type limitConn struct {
	net.Conn
	max      int
	count    int  // bytes of the current record so far
	afterIAC bool // the last byte read was an unescaped IAC
	err      error
}

func (c *limitConn) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	n, err := c.Conn.Read(p)
	for _, b := range p[:n] {
		if c.afterIAC {
			c.afterIAC = false
			if b == eorByte {
				c.count = 0
				continue
			}
		} else if b == iacByte {
			c.afterIAC = true
		}
		c.count++
		if c.count > c.max {
			c.err = ErrRecordTooLarge
			return 0, c.err
		}
	}
	return n, err
}

// tn3270eOutboundHeader is the mandatory 5-byte TN3270E message header
// (RFC 2355 SS 3.1) this server sends in front of every outbound 3270
// datastream message once TN3270E is active: DATA-TYPE 3270-DATA (0x00),
// no request/response flags, SEQ-NUMBER 0x0000. We never need the client
// to acknowledge our screens, so RESPONSE-FLAG is always NO-RESPONSE and
// the sequence number never needs to advance (or be escaped: it's never
// 0xff).
var tn3270eOutboundHeader = []byte{0x00, 0x00, 0x00, 0x00, 0x00}

// tn3270eDataConn wraps a connection on which TN3270E's DEVICE-TYPE/
// FUNCTIONS negotiation has already completed, adding tn3270eOutboundHeader
// to every 3270-datastream write and transparently stripping the header
// TN3270E requires the client to prefix on its reply, before handing the
// rest to go3270's own (header-unaware) reader.
//
// It has to stay active through go3270.NegotiateTelnet itself, not just
// the screen loop after it: go3270's own device-info probe (an Erase/Write
// Alternate plus a Read-Partition-Query, used to detect the terminal's
// real alternate-screen size) is itself a 3270-datastream exchange, and at
// least one real client (s3270) starts framing its replies the moment
// TN3270E's own negotiation completes -- well before go3270 finishes its
// unrelated base telnet option negotiation (terminal-type/EOR/BINARY).
// Those base-option messages are always IAC-prefixed telnet commands,
// never TN3270E-framed by either side, so this only adds/strips a header
// around writes/reads that *aren't* IAC-prefixed -- the plain 3270 data.
type tn3270eDataConn struct {
	net.Conn
	pendingHeaderBytes int
}

func (c *tn3270eDataConn) Write(p []byte) (int, error) {
	if len(p) > 0 && p[0] == iacByte {
		// A telnet command (WILL/DO/WONT/DONT/SB), not 3270 data.
		return c.Conn.Write(p)
	}

	n, err := c.Conn.Write(append(append([]byte{}, tn3270eOutboundHeader...), p...))
	c.pendingHeaderBytes = len(tn3270eOutboundHeader)

	written := n - len(tn3270eOutboundHeader)
	if written < 0 {
		written = 0
	}
	return written, err
}

func (c *tn3270eDataConn) Read(p []byte) (int, error) {
	for c.pendingHeaderBytes > 0 {
		if _, err := readEscapedByte(c.Conn); err != nil {
			return 0, err
		}
		c.pendingHeaderBytes--
	}
	return c.Conn.Read(p)
}

// readEscapedByte reads one logical byte from a fixed-length, unterminated
// TN3270E header field, applying the IAC IAC -> literal 0xff escape a
// literal 0xff header byte (e.g. part of a nonzero SEQ-NUMBER) requires.
// Unlike readSBByte, there's no IAC SE terminator to watch for here: header
// fields have a known fixed length instead.
func readEscapedByte(conn net.Conn) (byte, error) {
	buf := make([]byte, 1)
	if err := readFullN(conn, buf); err != nil {
		return 0, err
	}
	if buf[0] != iacByte {
		return buf[0], nil
	}
	if err := readFullN(conn, buf); err != nil {
		return 0, err
	}
	return buf[0], nil
}
