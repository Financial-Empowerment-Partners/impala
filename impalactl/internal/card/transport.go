// Package card talks to an Impala card applet over the impala-card simulator
// transport: a TCP socket where every command APDU and every response
// (data ‖ SW1 SW2) is framed by a 2-byte big-endian length
// (impala-card SimulatorApduServer; demo/scripts/simulator.sh probes it the
// same way). The commands are the card SDK's (impala-card/sdk ImpalaSDK.kt)
// with the byte layouts of impala-card/docs/apdu.md and
// docs/sep10-card-keys.md §3.
//
// The transport is cleartext: a PIN sent with VERIFY_PIN crosses the socket
// as four digit values, as it crosses NFC.
package card

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Transport carries one APDU exchange at a time.
type Transport interface {
	Transmit(apdu []byte) ([]byte, error)
	Close() error
}

// ParseSpec reads a card address "tcp:HOST:PORT" (HOST may be a bracketed
// IPv6 literal).
func ParseSpec(spec string) (host, port string, err error) {
	rest, ok := strings.CutPrefix(spec, "tcp:")
	if !ok {
		return "", "", fmt.Errorf("card %q: expected tcp:HOST:PORT (the simulator transport)", spec)
	}
	host, port, err = net.SplitHostPort(rest)
	if err != nil || host == "" {
		return "", "", fmt.Errorf("card %q: expected tcp:HOST:PORT", spec)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("card %q: bad port", spec)
	}
	return host, port, nil
}

// TCP is the length-prefixed simulator transport.
type TCP struct {
	conn    net.Conn
	timeout time.Duration
}

// DialTCP connects to a card at "tcp:HOST:PORT". timeout bounds the dial and
// each exchange.
func DialTCP(spec string, timeout time.Duration) (*TCP, error) {
	host, port, err := ParseSpec(spec)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to the card at %s: %w", spec, err)
	}
	return &TCP{conn: conn, timeout: timeout}, nil
}

// Transmit sends one framed APDU and reads one framed response.
func (t *TCP) Transmit(apdu []byte) ([]byte, error) {
	if len(apdu) > 0xFFFF {
		return nil, errors.New("APDU too long for the framing")
	}
	if t.timeout > 0 {
		_ = t.conn.SetDeadline(time.Now().Add(t.timeout))
	}
	frame := make([]byte, 2+len(apdu))
	binary.BigEndian.PutUint16(frame, uint16(len(apdu)))
	copy(frame[2:], apdu)
	_, err := t.conn.Write(frame)
	clear(frame) // the frame may carry a PIN or key material, like the APDU
	if err != nil {
		return nil, err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(t.conn, hdr[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(t.conn, resp); err != nil {
		return nil, err
	}
	if len(resp) < 2 {
		return nil, fmt.Errorf("a %d-byte response has no status word", len(resp))
	}
	return resp, nil
}

// Close closes the connection (the simulator deselects the applet).
func (t *TCP) Close() error { return t.conn.Close() }

// IsLoopback reports whether a card spec's host is a loopback address or
// "localhost".
func IsLoopback(spec string) bool {
	host, _, err := ParseSpec(spec)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
