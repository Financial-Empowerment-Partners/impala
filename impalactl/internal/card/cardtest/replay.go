package cardtest

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
)

// A Recording is a card session captured between a host and the real applet
// (internal/card/testdata/issuance-*.txt): '# key=value' header lines, then
// '> command' / '< answer' hex lines in order.
type Recording struct {
	Header    map[string]string
	Exchanges []Exchange
}

// Exchange is one recorded command and the card's answer (data ‖ SW).
type Exchange struct {
	Command, Answer []byte
}

// LoadRecording parses a recording file.
func LoadRecording(path string) (*Recording, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rec := &Recording{Header: map[string]string{}}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "":
		case strings.HasPrefix(line, "#"):
			if k, v, ok := strings.Cut(strings.TrimSpace(line[1:]), "="); ok && !strings.Contains(k, " ") {
				rec.Header[k] = v
			}
		case strings.HasPrefix(line, ">"), strings.HasPrefix(line, "<"):
			b, err := hex.DecodeString(strings.TrimSpace(line[1:]))
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %v", path, n, err)
			}
			if line[0] == '>' {
				rec.Exchanges = append(rec.Exchanges, Exchange{Command: b})
			} else {
				if len(rec.Exchanges) == 0 || rec.Exchanges[len(rec.Exchanges)-1].Answer != nil {
					return nil, fmt.Errorf("%s:%d: an answer without a command", path, n)
				}
				rec.Exchanges[len(rec.Exchanges)-1].Answer = b
			}
		default:
			return nil, fmt.Errorf("%s:%d: unknown line", path, n)
		}
	}
	return rec, sc.Err()
}

// Randomness is what the host drew, in the order it was sent: the INITIALIZE
// seed (00 2C) and every INITIALIZE UPDATE host challenge (80 50).
func (r *Recording) Randomness() []byte {
	var out []byte
	for _, e := range r.Exchanges {
		c := e.Command
		if len(c) > 5 && ((c[0] == 0x00 && c[1] == 0x2C) || (c[0] == 0x80 && c[1] == 0x50)) {
			out = append(out, c[5:5+int(c[4])]...)
		}
	}
	return out
}

// LastAnswer returns the data (without SW) of the last answer to a command
// starting with prefix, or nil.
func (r *Recording) LastAnswer(prefix []byte) []byte {
	for i := len(r.Exchanges) - 1; i >= 0; i-- {
		if bytes.HasPrefix(r.Exchanges[i].Command, prefix) {
			a := r.Exchanges[i].Answer
			return a[:len(a)-2]
		}
	}
	return nil
}

// Replay is a card that answers SELECT with 9000 and otherwise requires each
// command to equal the next recorded one byte for byte, returning the
// recorded answer. A difference is recorded (both hex strings) and answered
// 6F00, and every later command fails too.
type Replay struct {
	rec *Recording

	mu       sync.Mutex
	next     int
	failures []string
	broken   bool
}

// NewReplay returns a replay card for rec.
func NewReplay(rec *Recording) *Replay { return &Replay{rec: rec} }

// Start serves the replay card on 127.0.0.1 and returns its spec.
func (r *Replay) Start(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(conn)
		}
	}()
	return "tcp:" + ln.Addr().String()
}

// Consumed is how many recorded exchanges were matched.
func (r *Replay) Consumed() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.next
}

// Failures lists every command that did not match.
func (r *Replay) Failures() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.failures...)
}

func (r *Replay) answer(apdu []byte) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(apdu) >= 4 && apdu[0] == 0x00 && apdu[1] == 0xA4 && apdu[2] == 0x04 {
		return []byte{0x90, 0x00}
	}
	switch {
	case r.broken:
		r.failures = append(r.failures, fmt.Sprintf("after a mismatch: %x", apdu))
	case r.next >= len(r.rec.Exchanges):
		r.failures = append(r.failures, fmt.Sprintf("command %d is past the end of the recording: %x", r.next+1, apdu))
		r.broken = true
	case !bytes.Equal(apdu, r.rec.Exchanges[r.next].Command):
		r.failures = append(r.failures, fmt.Sprintf("command %d:\n  got  %x\n  want %x", r.next+1, apdu, r.rec.Exchanges[r.next].Command))
		r.broken = true
	default:
		a := r.rec.Exchanges[r.next].Answer
		r.next++
		return append([]byte(nil), a...)
	}
	return []byte{0x6F, 0x00}
}

func (r *Replay) serve(conn net.Conn) {
	defer conn.Close()
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		apdu := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(conn, apdu); err != nil {
			return
		}
		resp := r.answer(apdu)
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}
