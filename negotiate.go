// Package tn3270e adds TN3270E (RFC 2355) server-side negotiation, and
// workarounds for real-world client quirks, on top of
// github.com/racingmars/go3270, which only speaks plain TN3270.
//
// Call Negotiate on a freshly accepted connection, then use the returned
// Result's Conn and DevInfo with go3270's screen functions (ShowScreenOpts
// etc.) exactly as you would a plain go3270 connection.
package tn3270e

import (
	"fmt"
	"net"
	"time"

	"github.com/racingmars/go3270"
)

// tn3270eHandshakeTimeout bounds the DEVICE-TYPE/FUNCTIONS exchange once the
// client has agreed to TN3270E.
const tn3270eHandshakeTimeout = 5 * time.Second

// Result is the outcome of a successful Negotiate.
type Result struct {
	// Conn is the connection to use for everything after negotiation. It
	// wraps the connection passed to Negotiate, adding and stripping
	// TN3270E message headers when TN3270E is active.
	Conn net.Conn

	// DevInfo is the terminal information go3270.NegotiateTelnet reported,
	// including the alternate screen size and codepage.
	DevInfo go3270.DevInfo

	// TN3270E reports whether TN3270E was negotiated. When false, the
	// client is speaking plain TN3270 and LUName and DeviceType are empty.
	TN3270E bool

	// LUName is the LU name assigned to the client during TN3270E
	// negotiation (the luName passed to Negotiate).
	LUName string

	// DeviceType is the device type the client requested during TN3270E
	// negotiation, e.g. "IBM-3278-2-E".
	DeviceType string
}

// Negotiate performs server-side telnet negotiation on a freshly accepted
// connection: TN3270E first, if the client is willing to speak it
// (assigning it luName), then go3270's own plain-TN3270 negotiation
// (terminal type, EOR, BINARY, and the alternate-screen-size query).
//
// A client that doesn't speak TN3270E falls back to plain TN3270; that is
// not an error.
func Negotiate(conn net.Conn, luName string) (Result, error) {
	c, deviceType, active, err := negotiateTN3270E(coalescingConn{conn}, luName)
	if err != nil {
		return Result{}, fmt.Errorf("TN3270E negotiation: %w", err)
	}
	if active {
		// At least one real client (s3270) starts framing its replies in
		// the TN3270E per-message header the moment its side of FUNCTIONS
		// negotiation completes -- including its reply to go3270's own
		// alt-screen-size probe inside NegotiateTelnet below, which is
		// itself a 3270-datastream exchange (not base telnet option
		// negotiation). tn3270eDataConn has to be in place for that whole
		// call, not just the screen I/O after it, or that probe reply
		// gets read unstripped and NegotiateTelnet silently falls back to
		// the base 24x80 screen.
		c = &tn3270eDataConn{Conn: c}
	}

	devinfo, err := go3270.NegotiateTelnet(c)
	if err != nil {
		return Result{}, fmt.Errorf("telnet negotiation: %w", err)
	}

	res := Result{Conn: c, DevInfo: devinfo, TN3270E: active}
	if active {
		res.LUName = luName
		res.DeviceType = deviceType
	}
	return res, nil
}
