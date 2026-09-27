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
