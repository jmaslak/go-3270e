# go-3270e

Server-side TN3270E (RFC 2355) negotiation for
[`github.com/racingmars/go3270`](https://github.com/racingmars/go3270),
which on its own only speaks plain TN3270.

It also works around client quirks seen in practice:

- Clients (e.g. dx3270) that offer TN3270E, and send their DEVICE-TYPE
  REQUEST, without waiting to be asked.
- Clients (e.g. s3270) that start using TN3270E message headers before
  go3270's own telnet negotiation has finished.
- Clients whose negotiation replies arrive split across several TCP reads,
  which go3270's single-`Read` negotiation code would otherwise reject.

Clients that don't speak TN3270E fall back to plain TN3270.

No optional TN3270E functions (BIND-IMAGE, DATA-STREAM-CTL, RESPONSES,
SCS-CTL-CODES, SYSREQ) are supported; negotiation always settles on basic
TN3270E.

## Usage

```go
import (
	"github.com/racingmars/go3270"
	tn3270e "github.com/jmaslak/go-3270e"
)

func handle(conn net.Conn) {
	defer conn.Close()

	neg, err := tn3270e.Negotiate(conn, "LU000001")
	if err != nil {
		log.Print(err)
		return
	}

	// Use neg.Conn (not conn) from here on.
	go3270.ShowScreenOpts(screen, nil, neg.Conn, go3270.ScreenOpts{
		AltScreen: neg.DevInfo, Codepage: neg.DevInfo.Codepage(),
	})
}
```

`Negotiate` returns the connection to use from then on, go3270's
`DevInfo`, whether TN3270E was negotiated, and the assigned LU name and
the client's requested device type (empty for plain TN3270).

## Choosing the LU name

A TN3270E client may ask to connect to a particular resource name. To
decide what to assign based on that request, use `NegotiateLU` with an
`LUChooser` instead of `Negotiate`:

```go
neg, err := tn3270e.NegotiateLU(conn, func(requested string) (string, error) {
	switch {
	case requested == "":
		return nextFreeLU(), nil
	case !validLU(requested):
		return "", fmt.Errorf("unknown LU %q", requested)
	case inUse(requested):
		return "", fmt.Errorf("LU %q: %w", requested, tn3270e.ErrDeviceInUse)
	}
	return requested, nil
})
```

`requested` is empty if the client named no resource. The chooser isn't
called for plain TN3270 clients, since they can't name one.

If the chooser returns an error, the client is sent DEVICE-TYPE REJECT.
The reason is DEVICE-IN-USE if `errors.Is(err, tn3270e.ErrDeviceInUse)`,
and INV-NAME for any other error. The client may then ask again, with
another name or none. Negotiation fails after 3 refused requests.
`Result.RequestedLU` holds the name the client asked for, and
`Result.LUName` holds the name it was assigned.

## Limits

- `Negotiate` fails if negotiation takes longer than 30 seconds.
- Reads on the connection fail with `ErrRecordTooLarge` once the client
  sends a single record (data up to IAC EOR) longer than `MaxRecordSize`
  (512 KiB). This bounds how much go3270's `ShowScreenOpts` and friends
  will buffer for one response. It covers any Read Modified or Read
  Buffer reply, for every screen size go3270 supports.

Connection limits, and limits on expensive work such as password
hashing, are up to the server using this package.
