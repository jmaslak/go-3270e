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
