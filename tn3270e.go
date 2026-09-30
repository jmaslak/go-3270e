package tn3270e

import (
	"fmt"
	"net"
	"time"
)

// TN3270E (RFC 2355) subnegotiation message-type bytes, sent inside
// IAC SB TN3270E ... IAC SE. go3270 has no notion of these -- it only
// speaks plain TN3270 -- so we drive this whole exchange ourselves before
// handing the connection to go3270.NegotiateTelnet.
const (
	sbByte = 250
	seByte = 240

	tnAssociate  = 0
	tnConnect    = 1
	tnDeviceType = 2
	tnFunctions  = 3
	tnIs         = 4
	tnReason     = 5
	tnReject     = 6
	tnRequest    = 7
	tnSend       = 8

	// reasonInvName is the DEVICE-TYPE REJECT reason code for a resource
	// name the server will not assign (RFC 2355 SS 4.3: INV-NAME).
	reasonInvName = 3

	// deviceTypeTries is how many DEVICE-TYPE REQUESTs a client may make,
	// each refused one being answered with REJECT, before negotiation
	// fails.
	deviceTypeTries = 3
)

// handshake is what the DEVICE-TYPE subnegotiation settled on.
type handshake struct {
	deviceType string
	requested  string // the resource name the client asked to CONNECT to, if any
	luName     string // the name assigned
}

// negotiateTN3270E establishes TN3270E (telnet option 40) if the client is
// willing to speak it, then drives the DEVICE-TYPE and FUNCTIONS
// subnegotiations to completion, assigning the connection the name choose
// picks given the resource name the client requested -- the server has
// final say over the assigned device-name per RFC 2355 SS 4.3.
//
// By convention (RFC 2355 SS 4), the server offers TN3270E first, so this
// always sends "IAC DO TN3270E" up front for a client that's waiting to be
// asked (observed with s3270). Some clients instead offer it unprompted
// (observed with dx3270, which sends "IAC WILL TN3270E" in its very first
// burst without waiting for a DO) -- that's handled too, since the scan
// below recognizes either side's WILL/DO for option 40 appearing in the
// drained burst, in whatever order it arrives.
//
// If the client doesn't speak TN3270E at all, this is a no-op: active is
// false and conn is returned unchanged (with any drained bytes, e.g. an
// unprompted WILL TERMINAL-TYPE, replayed for go3270.NegotiateTelnet to
// see).
func negotiateTN3270E(conn net.Conn, choose LUChooser) (result net.Conn, hs handshake, active bool, err error) {
	if _, werr := conn.Write([]byte{iacByte, doByte, tn3270EOption}); werr != nil {
		return conn, hs, false, werr
	}

	buf := readTN3270EReply(conn)

	offered := false
	var earlyDeviceTypeRequest []byte
	var kept []byte
	for i := 0; i < len(buf); {
		if i+2 < len(buf) && buf[i] == iacByte && buf[i+2] == tn3270EOption {
			switch buf[i+1] {
			case willByte:
				offered = true // this is the client's answer to our DO
				i += 3
				continue
			case doByte:
				// The client is asking us to also enable 40; reply WILL.
				if _, werr := conn.Write([]byte{iacByte, willByte, tn3270EOption}); werr != nil {
					return conn, hs, false, werr
				}
				offered = true
				i += 3
				continue
			case wontByte, dontByte:
				// Explicit decline; nothing more to send.
				i += 3
				continue
			case sbByte:
				// Some clients (observed with dx3270) don't wait for our
				// own SEND DEVICE-TYPE before answering: they bundle their
				// DEVICE-TYPE REQUEST in this same initial burst, right
				// alongside their WILL. Extract it now, since our own
				// read in runTN3270EHandshake below only sees fresh bytes
				// arriving *after* this point -- it would otherwise block
				// forever waiting for a reply the client already sent.
				if payload, consumed, ok := extractSBPayload(buf[i:]); ok {
					offered = true
					earlyDeviceTypeRequest = payload
					i += consumed
					continue
				}
			}
		}
		kept = append(kept, buf[i])
		i++
	}

	if !offered {
		if len(kept) == 0 {
			return conn, hs, false, nil
		}
		return &prefixConn{Conn: conn, prefix: kept}, hs, false, nil
	}

	// kept holds bytes the client sent before/alongside its TN3270E offer
	// (e.g. an unprompted WILL TERMINAL-TYPE, observed from a real
	// client) -- they belong to go3270.NegotiateTelnet's later plain-
	// telnet negotiation, not to the DEVICE-TYPE/FUNCTIONS exchange below,
	// which expects the client's actual next bytes on the wire to be its
	// own subnegotiation reply.
	_ = conn.SetReadDeadline(time.Now().Add(tn3270eHandshakeTimeout))
	hs, handshakeErr := runTN3270EHandshake(conn, choose, earlyDeviceTypeRequest)
	_ = conn.SetReadDeadline(time.Time{})
	if handshakeErr != nil {
		return conn, hs, false, handshakeErr
	}

	result = conn
	if len(kept) > 0 {
		result = &prefixConn{Conn: conn, prefix: kept}
	}
	return result, hs, true, nil
}

// runTN3270EHandshake drives the DEVICE-TYPE and FUNCTIONS subnegotiations
// (RFC 2355 SS 4.3, 5.3) once telnet option 40 itself has been accepted.
// earlyDeviceTypeRequest, if non-nil, is a DEVICE-TYPE REQUEST payload the
// caller already extracted from the client's initial burst (some clients,
// observed with dx3270, send this unprompted rather than waiting for our
// own SEND DEVICE-TYPE) -- when set, it's used directly instead of
// blocking on a read for a reply that already arrived and won't repeat.
//
// A request choose refuses is answered with DEVICE-TYPE REJECT (reason
// INV-NAME), and the client may make another, up to deviceTypeTries in
// all.
func runTN3270EHandshake(conn net.Conn, choose LUChooser, earlyDeviceTypeRequest []byte) (hs handshake, err error) {
	// SEND DEVICE-TYPE is the one message in this exchange where the verb
	// (SEND) precedes the topic (DEVICE-TYPE); every other message here
	// (DEVICE-TYPE IS/REQUEST, FUNCTIONS IS/REQUEST) puts the topic first.
	// We still send it even if earlyDeviceTypeRequest is already set, for
	// protocol conformance -- a client that already answered will just
	// ignore it.
	if _, werr := conn.Write([]byte{iacByte, sbByte, tn3270EOption, tnSend, tnDeviceType, iacByte, seByte}); werr != nil {
		return hs, werr
	}

	payload := earlyDeviceTypeRequest
	for try := 1; ; try++ {
		if payload == nil {
			var rerr error
			payload, rerr = readTN3270ESBMessage(conn)
			if rerr != nil {
				return hs, fmt.Errorf("device-type request: %w", rerr)
			}
		}
		if len(payload) < 2 || payload[0] != tnDeviceType || payload[1] != tnRequest {
			return hs, fmt.Errorf("unexpected device-type reply: %x", payload)
		}
		hs = parseDeviceTypeRequest(payload[2:])
		name, cerr := choose(hs.requested)
		if cerr == nil {
			hs.luName = name
			break
		}
		if try >= deviceTypeTries {
			return hs, fmt.Errorf("device name %q refused: %w", hs.requested, cerr)
		}
		reject := []byte{iacByte, sbByte, tn3270EOption, tnDeviceType, tnReject, tnReason, reasonInvName, iacByte, seByte}
		if _, werr := conn.Write(reject); werr != nil {
			return hs, werr
		}
		payload = nil
	}

	reply := []byte{iacByte, sbByte, tn3270EOption, tnDeviceType, tnIs}
	reply = append(reply, []byte(hs.deviceType)...)
	reply = append(reply, tnConnect)
	reply = append(reply, []byte(hs.luName)...)
	reply = append(reply, iacByte, seByte)
	if _, werr := conn.Write(reply); werr != nil {
		return hs, werr
	}

	payload, rerr := readTN3270ESBMessage(conn)
	if rerr != nil {
		return hs, fmt.Errorf("functions request: %w", rerr)
	}
	if len(payload) < 2 || payload[0] != tnFunctions || payload[1] != tnRequest {
		return hs, fmt.Errorf("unexpected functions message: %x", payload)
	}
	agreed := decideFunctions(payload[2:])

	reply = []byte{iacByte, sbByte, tn3270EOption, tnFunctions, tnIs}
	reply = append(reply, agreed...)
	reply = append(reply, iacByte, seByte)
	if _, werr := conn.Write(reply); werr != nil {
		return hs, werr
	}
	return hs, nil
}

// parseDeviceTypeRequest reads the body of a DEVICE-TYPE REQUEST, after
// its message-type bytes: the device type, then optionally CONNECT and the
// resource name asked for, or ASSOCIATE and a device name (for a printer),
// which is not a name asked for.
func parseDeviceTypeRequest(body []byte) handshake {
	for i, b := range body {
		switch b {
		case tnConnect:
			return handshake{deviceType: string(body[:i]), requested: string(body[i+1:])}
		case tnAssociate:
			return handshake{deviceType: string(body[:i])}
		}
	}
	return handshake{deviceType: string(body)}
}

// decideFunctions decides which TN3270E functions (RFC 2355 SS 5.4) this
// server will agree to support, given the raw function-code list the
// client sent in its FUNCTIONS REQUEST. The result is echoed back verbatim
// in our own FUNCTIONS IS reply, which -- per RFC 2355 SS 5.3 -- settles
// the negotiation immediately as long as it doesn't itself add back a
// function the client's request removed (it's fine to remove more; a
// multi-round REQUEST/REQUEST haggle is only needed to propose additions,
// which we have no reason to do).
//
// The function codes that can appear in requested are:
//
//	0 BIND-IMAGE       1 DATA-STREAM-CTL   2 RESPONSES
//	3 SCS-CTL-CODES    4 SYSREQ
//
// Each one is an obligation, not just a label: e.g. agreeing to RESPONSES
// means the client may expect a RESPONSE message for any data message it
// flags ALWAYS-RESPONSE, which this server's outbound writes never send
// (tn3270eOutboundHeader is hardcoded to NO-RESPONSE) -- so claiming to
// support a function whose behavior isn't actually implemented is exactly
// the kind of protocol gap that's easy to overlook.
func decideFunctions(requested []byte) []byte {
	// We implement none of RFC 2355's optional functions (BIND-IMAGE,
	// DATA-STREAM-CTL, RESPONSES, SCS-CTL-CODES, SYSREQ), so always decline
	// whatever the client proposed rather than claim support we don't have.
	// An empty list is legal per RFC 2355 SS 5.3 ("basic TN3270E") and a
	// narrower reply than the client's request settles the negotiation in
	// this one round, with no REQUEST/REQUEST haggling needed.
	return nil
}

// extractSBPayload parses one complete "IAC SB TN3270E ... IAC SE"
// subnegotiation out of an in-memory buffer (buf[0:3] must already be that
// exact prefix), applying the same IAC-IAC escape readSBByte does for a
// live connection. It returns the payload (the message-type byte onward),
// how many bytes of buf it consumed, and whether a complete message was
// actually found -- ok is false if the buffer ends before a terminating
// IAC SE turns up, e.g. because the client's message was split across a
// TCP segment boundary drainAvailable didn't wait long enough to coalesce.
func extractSBPayload(buf []byte) (payload []byte, consumed int, ok bool) {
	if len(buf) < 3 || buf[0] != iacByte || buf[1] != sbByte || buf[2] != tn3270EOption {
		return nil, 0, false
	}
	for i := 3; i < len(buf); {
		if buf[i] != iacByte {
			payload = append(payload, buf[i])
			i++
			continue
		}
		if i+1 >= len(buf) {
			return nil, 0, false
		}
		if buf[i+1] == iacByte {
			payload = append(payload, iacByte)
			i += 2
			continue
		}
		// Unescaped IAC followed by anything else ends the
		// subnegotiation; in practice this is always SE.
		return payload, i + 2, true
	}
	return nil, 0, false
}

// readTN3270ESBMessage reads one complete IAC SB TN3270E ... IAC SE
// subnegotiation and returns the bytes between TN3270E's option byte and
// the terminating IAC SE (i.e. the message-type byte onward).
func readTN3270ESBMessage(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 3)
	if err := readFullN(conn, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != iacByte || hdr[1] != sbByte || hdr[2] != tn3270EOption {
		return nil, fmt.Errorf("expected IAC SB TN3270E, got %x", hdr)
	}

	var payload []byte
	for {
		b, end, err := readSBByte(conn)
		if err != nil {
			return nil, err
		}
		if end {
			return payload, nil
		}
		payload = append(payload, b)
	}
}

// readSBByte reads one byte of a telnet subnegotiation's payload, applying
// the standard IAC IAC -> literal 0xff escape, and reports end=true once it
// consumes the terminating (unescaped) IAC SE instead of a payload byte.
func readSBByte(conn net.Conn) (b byte, end bool, err error) {
	buf := make([]byte, 1)
	if err := readFullN(conn, buf); err != nil {
		return 0, false, err
	}
	if buf[0] != iacByte {
		return buf[0], false, nil
	}

	if err := readFullN(conn, buf); err != nil {
		return 0, false, err
	}
	if buf[0] == iacByte {
		return iacByte, false, nil
	}
	// Anything other than a doubled IAC ends the subnegotiation; in
	// practice this is always SE.
	return 0, true, nil
}

// readFullN blocks until buf is completely filled or an error occurs.
func readFullN(conn net.Conn, buf []byte) error {
	for total := 0; total < len(buf); {
		n, err := conn.Read(buf[total:])
		total += n
		if total == len(buf) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}
