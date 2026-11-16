package card_test

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"impalactl/internal/card"
	"impalactl/internal/card/cardtest"
)

func open(t *testing.T, c *cardtest.Card) *card.Card {
	t.Helper()
	tr, err := card.DialTCP(c.Start(t), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cd := card.New(tr)
	t.Cleanup(func() { cd.Close() })
	if err := cd.Select(card.DefaultAID); err != nil {
		t.Fatal(err)
	}
	return cd
}

// The SDK's parts (ImpalaSDK.signSep10): BEGIN = networkId + min(n-1, 223)
// bytes, CONTINUE 255 while more than 255 remain, FINISH the rest (>= 1).
func TestSignSep10Chunking(t *testing.T) {
	for n, want := range map[int][]int{
		2:   {33, 1},
		224: {255, 1},
		225: {255, 2},
		478: {255, 255},
		479: {255, 255, 1},
		640: {255, 255, 162},
	} {
		c := cardtest.New(t)
		cd := open(t, c)
		_, _ = cd.SignSep10(make([]byte, 32), make([]byte, n)) // zeros: the card refuses at FINISH
		got := c.Sep10Parts()
		if len(got) != len(want) {
			t.Errorf("n=%d parts %v, want %v", n, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("n=%d parts %v, want %v", n, got, want)
				break
			}
		}
	}
}

func TestIdentityAndRefusals(t *testing.T) {
	c := cardtest.New(t)
	cd := open(t, c)
	id, err := card.ReadIdentity(cd)
	if err != nil {
		t.Fatal(err)
	}
	if id.WireCardID() != "ea94fa5b0f6b2abc1626bc50c0bd5e17" || id.AccountUUID() != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Errorf("identity = %s %s", id.WireCardID(), id.AccountUUID())
	}
	if !id.HasStellarKey() || id.RequireSigner() != nil {
		t.Error("flags")
	}
	err = cd.VerifyUserPIN("0000")
	if card.SWOf(err) != 0x69C4 || !strings.Contains(err.Error(), "verify the user PIN (VERIFY_PIN): SW 69C4 WRONG_PIN: 4 tries left") {
		t.Errorf("wrong PIN: %v", err)
	}
	if _, err := cd.SignAuth(make([]byte, 32), true); card.SWOf(err) != 0x6690 {
		t.Errorf("PIN proof without VERIFY_PIN: %v", err)
	}
	if err := cd.VerifyUserPIN("1234"); err != nil {
		t.Fatal(err)
	}
	if _, err := cd.SignAuth(make([]byte, 32), true); err != nil {
		t.Errorf("PIN proof after VERIFY_PIN: %v", err)
	}
	if err := cd.Select("A000000000"); card.SWOf(err) != 0x6A82 {
		t.Errorf("unknown AID: %v", err)
	}
}

func TestSpecParsing(t *testing.T) {
	for _, bad := range []string{"127.0.0.1:9025", "tcp:127.0.0.1", "tcp::9025", "tcp:h:0", "udp:h:1"} {
		if _, _, err := card.ParseSpec(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if !card.IsLoopback("tcp:127.0.0.1:9025") || !card.IsLoopback("tcp:[::1]:9025") || card.IsLoopback("tcp:10.0.2.2:9025") {
		t.Error("loopback detection")
	}
}

// A wrapped command that answers data: the response carries R-ENC and an
// R-MAC (the fake card's wrapResponse), which the host verifies and
// decrypts; the MAC chain then carries on into the next command.
func TestSecureChannelUnwrapsADataResponse(t *testing.T) {
	c := cardtest.NewBlank(t)
	cd := open(t, c)
	keys := card.DefaultSCP03Keys()
	sc, err := cd.OpenSecureChannel(&keys, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	for i := 0; i < 2; i++ {
		d, err := sc.Transmit("read the version", "GET_VERSION", 0x64, 0, 0, nil)
		if err != nil || len(d) != 10 || d[3] != 4 {
			t.Fatalf("wrapped GET_VERSION %d: %x, %v", i, d, err)
		}
	}
	d, err := sc.Transmit("read the user data", "GET_USER_DATA", 0x1E, 0, 0, nil)
	if err != nil || len(d) != 32+len("Test Holder") {
		t.Fatalf("wrapped GET_USER_DATA: %x, %v", d, err)
	}
	// A card refusal through the channel is a card error with its SW.
	if _, err := sc.Transmit("personalize", "PERSONALIZE", 0x72, 0x01, 0, make([]byte, 40)); card.SWOf(err) != 0x6230 {
		t.Errorf("PERSONALIZE on a blank card: %v", err)
	}
	// Other keys: the cryptogram does not verify and nothing more is sent.
	other := card.SCP03Keys{}
	other.ENC[0] = 1
	before := c.Count("EXTERNAL_AUTHENTICATE")
	var ce *card.CryptogramError
	if _, err := cd.OpenSecureChannel(&other, rand.Reader); !errors.As(err, &ce) || c.Count("EXTERNAL_AUTHENTICATE") != before {
		t.Errorf("wrong keys: %v", err)
	}
}
