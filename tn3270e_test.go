package tn3270e

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

func TestParseDeviceTypeRequest(t *testing.T) {
	for in, want := range map[string]handshake{
		"IBM-3278-2-E":            {deviceType: "IBM-3278-2-E"},
		"IBM-3278-2-E\x01CONSOLE": {deviceType: "IBM-3278-2-E", requested: "CONSOLE"},
		"IBM-3287-1\x00PRINTER1":  {deviceType: "IBM-3287-1"},
		"IBM-DYNAMIC\x01":         {deviceType: "IBM-DYNAMIC"},
	} {
		if got := parseDeviceTypeRequest([]byte(in)); got != want {
			t.Errorf("%q: %+v, want %+v", in, got, want)
		}
	}
}

// sb frames a TN3270E subnegotiation.
func sb(body ...byte) []byte {
	return append(append([]byte{iacByte, sbByte, tn3270EOption}, body...), iacByte, seByte)
}

// client plays a TN3270E client's side of the handshake: it reads what the
// server sends, answering SEND DEVICE-TYPE and each REJECT with the next of
// requests, and a DEVICE-TYPE IS with a FUNCTIONS REQUEST. It returns every
// message the server sent.
func client(t *testing.T, conn net.Conn, requests [][]byte) <-chan [][]byte {
	out := make(chan [][]byte, 1)
	go func() {
		var got [][]byte
		defer func() { out <- got }()
		next := 0
		send := func() bool {
			if next >= len(requests) {
				return false
			}
			_, err := conn.Write(sb(append([]byte{tnDeviceType, tnRequest}, requests[next]...)...))
			next++
			return err == nil
		}
		for {
			msg, err := readTN3270ESBMessage(conn)
			if err != nil {
				return
			}
			got = append(got, msg)
			switch {
			case bytes.Equal(msg, []byte{tnSend, tnDeviceType}), len(msg) > 1 && msg[0] == tnDeviceType && msg[1] == tnReject:
				if !send() {
					conn.Close() //nolint:errcheck
					return
				}
			case len(msg) > 1 && msg[0] == tnDeviceType && msg[1] == tnIs:
				_, _ = conn.Write(sb(tnFunctions, tnRequest, 2))
			case len(msg) > 1 && msg[0] == tnFunctions && msg[1] == tnIs:
				return
			}
		}
	}()
	return out
}

func TestHandshakeRejectsAndRetries(t *testing.T) {
	server, cl := net.Pipe()
	defer server.Close() //nolint:errcheck
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	msgs := client(t, cl, [][]byte{[]byte("IBM-3278-2-E\x01CONSOLE"), []byte("IBM-3278-2-E")})

	var asked []string
	hs, err := runTN3270EHandshake(server, func(requested string) (string, error) {
		asked = append(asked, requested)
		if requested == "CONSOLE" {
			return "", errors.New("not from there")
		}
		return "LU000001", nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hs.luName != "LU000001" || hs.requested != "" || hs.deviceType != "IBM-3278-2-E" || len(asked) != 2 || asked[0] != "CONSOLE" {
		t.Errorf("handshake %+v, asked %q", hs, asked)
	}
	got := <-msgs
	if len(got) < 3 || !bytes.Equal(got[1], []byte{tnDeviceType, tnReject, tnReason, reasonInvName}) {
		t.Fatalf("server sent %x; want SEND, REJECT INV-NAME, IS, FUNCTIONS IS", got)
	}
	if want := append([]byte{tnDeviceType, tnIs}, []byte("IBM-3278-2-E\x01LU000001")...); !bytes.Equal(got[2], want) {
		t.Errorf("device-type is %q, want %q", got[2], want)
	}
}

func TestHandshakeAssignsRequested(t *testing.T) {
	server, cl := net.Pipe()
	defer server.Close() //nolint:errcheck
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	msgs := client(t, cl, [][]byte{[]byte("IBM-3278-2-E\x01CONSOLE")})
	hs, err := runTN3270EHandshake(server, func(requested string) (string, error) { return requested, nil }, nil)
	if err != nil || hs.luName != "CONSOLE" || hs.requested != "CONSOLE" {
		t.Fatalf("handshake %+v, %v", hs, err)
	}
	<-msgs
}

func TestHandshakeGivesUp(t *testing.T) {
	server, cl := net.Pipe()
	defer server.Close() //nolint:errcheck
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	req := []byte("IBM-3278-2-E\x01CONSOLE")
	msgs := client(t, cl, [][]byte{req, req, req, req})
	_, err := runTN3270EHandshake(server, func(string) (string, error) { return "", errors.New("no") }, nil)
	if err == nil {
		t.Fatal("refused every time, yet negotiated")
	}
	cl.Close() //nolint:errcheck
	if got := <-msgs; len(got) != deviceTypeTries {
		t.Errorf("server sent %d messages, want SEND and %d REJECTs", len(got), deviceTypeTries-1)
	}
}

// A client far enough away that its WILL TN3270E arrives well after the
// DO went out must still get TN3270E, not be handed to plain-TN3270
// negotiation with its reply still in flight.
func TestNegotiateSlowClient(t *testing.T) {
	server, cl := net.Pipe()
	defer server.Close() //nolint:errcheck
	_ = cl.SetDeadline(time.Now().Add(5 * time.Second))

	msgs := make(chan [][]byte, 1)
	go func() {
		do := make([]byte, 3)
		if _, err := cl.Read(do); err != nil {
			close(msgs)
			return
		}
		time.Sleep(200 * time.Millisecond)
		_, _ = cl.Write([]byte{iacByte, willByte, tn3270EOption})
		msgs <- <-client(t, cl, [][]byte{[]byte("IBM-3278-2-E")})
	}()

	_, hs, active, err := negotiateTN3270E(server, func(string) (string, error) { return "LU000001", nil })
	if err != nil || !active || hs.luName != "LU000001" {
		t.Fatalf("active %v, handshake %+v, %v", active, hs, err)
	}
	<-msgs
}

// A client that refuses TN3270E is answered as soon as its WONT arrives,
// not after tn3270eReplyTimeout.
func TestNegotiateRefusedPromptly(t *testing.T) {
	server, cl := net.Pipe()
	defer server.Close() //nolint:errcheck
	defer cl.Close()     //nolint:errcheck

	go func() {
		do := make([]byte, 3)
		if _, err := cl.Read(do); err != nil {
			return
		}
		_, _ = cl.Write([]byte{iacByte, wontByte, tn3270EOption})
	}()

	start := time.Now()
	_, _, active, err := negotiateTN3270E(server, func(string) (string, error) { return "LU000001", nil })
	if err != nil || active {
		t.Fatalf("active %v, %v", active, err)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("took %v to accept a refusal", took)
	}
}

func TestLimitConn(t *testing.T) {
	record := append(bytes.Repeat([]byte{0x40}, 10), iacByte, iacByte) // escaped 0xff counts as data
	record = append(record, iacByte, eorByte)
	var in []byte
	for range 3 {
		in = append(in, record...)
	}
	in = append(in, bytes.Repeat([]byte{0x40}, 14)...)

	c := &limitConn{Conn: fakeConn{bytes.NewReader(in)}, max: 13}
	buf := make([]byte, 7)
	var read int
	var err error
	for err == nil {
		var n int
		n, err = c.Read(buf)
		read += n
	}
	if !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("got %v after %d bytes, want ErrRecordTooLarge", err, read)
	}
	if read < 3*len(record) {
		t.Errorf("only %d bytes read before failing; records within the limit should pass", read)
	}
	if _, err := c.Read(buf); !errors.Is(err, ErrRecordTooLarge) {
		t.Errorf("read after failure: %v, want ErrRecordTooLarge again", err)
	}
}

// fakeConn is a net.Conn whose reads come from r.
type fakeConn struct{ r *bytes.Reader }

func (f fakeConn) Read(p []byte) (int, error)     { return f.r.Read(p) }
func (fakeConn) Write(p []byte) (int, error)      { return len(p), nil }
func (fakeConn) Close() error                     { return nil }
func (fakeConn) LocalAddr() net.Addr              { return nil }
func (fakeConn) RemoteAddr() net.Addr             { return nil }
func (fakeConn) SetDeadline(time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error { return nil }

// A short read, which coalescingConn extends with deadlines of its own,
// must not wipe out the deadline its caller set.
func TestCoalescingKeepsCallerDeadline(t *testing.T) {
	server, cl := net.Pipe()
	defer server.Close() //nolint:errcheck
	defer cl.Close()     //nolint:errcheck
	go func() { _, _ = cl.Write([]byte{iacByte}) }()

	c := &coalescingConn{Conn: server}
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	done := make(chan error, 1)
	go func() { done <- readFullN(c, make([]byte, 3)) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read 3 bytes from a client that sent 1")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("caller's read deadline was lost")
	}
}

// A client that never stops sending can't hold Negotiate past
// negotiationTimeout.
func TestNegotiateTimesOut(t *testing.T) {
	defer func(d time.Duration) { negotiationTimeout = d }(negotiationTimeout)
	negotiationTimeout = 500 * time.Millisecond

	server, cl := net.Pipe()
	defer server.Close() //nolint:errcheck
	defer cl.Close()     //nolint:errcheck
	go func() {
		do := make([]byte, 3)
		if _, err := cl.Read(do); err != nil {
			return
		}
		if _, err := cl.Write([]byte{iacByte, willByte, tn3270EOption}); err != nil {
			return
		}
		for {
			time.Sleep(5 * time.Millisecond)
			if _, err := cl.Write([]byte{0}); err != nil {
				return
			}
		}
	}()

	done := make(chan error, 1)
	go func() {
		_, err := Negotiate(server, "LU000001")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("negotiated with a client that only sent garbage")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Negotiate ignored negotiationTimeout")
	}
}
