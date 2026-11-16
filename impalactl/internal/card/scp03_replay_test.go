package card_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"impalactl/internal/card"
	"impalactl/internal/card/cardtest"
)

// The card package's own commands, driven in the reference tool's order,
// reproduce a recorded ceremony with the real applet byte for byte: the
// SCP03 KDF, cryptograms, C-MAC chaining, counter ICV, C-DEC padding, the
// per-card key derivation and every payload layout. (The CLI's `card setup`
// replays the same files end to end in internal/cli.)
func TestSCP03AndPayloadsReplayTheRecordedCeremony(t *testing.T) {
	for _, name := range []string{"issuance-jc305-soft.txt", "issuance-jc32-native.txt"} {
		t.Run(name, func(t *testing.T) {
			rec, err := cardtest.LoadRecording("testdata/" + name)
			if err != nil {
				t.Fatal(err)
			}
			r := cardtest.NewReplay(rec)
			tr, err := card.DialTCP(r.Start(t), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			cd := card.New(tr)
			defer cd.Close()
			rnd := bytes.NewReader(rec.Randomness())
			h := rec.Header
			kmk, _ := hex.DecodeString(h["kmk"])
			account, _ := hex.DecodeString(strings.ReplaceAll(h["account"], "-", ""))
			tag, _ := card.CurrencyTag(h["currency"])
			counter, _ := strconv.Atoi(h["initial_counter"])
			final := rec.LastAnswer([]byte{0x00, 0x34})
			programID, issuerPub := final[2:18], final[22:87]
			cert, err := card.TrimDER(final[87:159])
			if err != nil {
				t.Fatal(err)
			}

			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("%v\n%s", err, strings.Join(r.Failures(), "\n"))
				}
			}
			_, err = cd.GetVersion()
			must(err)
			_, err = cd.GetPersonalization()
			must(err)
			must(cd.Initialize(rnd))
			_, cardID, err := cd.GetUserData()
			must(err)
			_, err = cd.GetECPubKey()
			must(err)
			perCard, err := card.CardKeys(kmk, cardID)
			must(err)
			_, err = cd.OpenSecureChannel(&perCard, rnd)
			var ce *card.CryptogramError
			if !errors.As(err, &ce) {
				t.Fatalf("per-card keys on a stock card: %v", err)
			}
			transport := card.DefaultSCP03Keys()
			sc, err := cd.OpenSecureChannel(&transport, rnd)
			must(err)
			must(sc.RotateKeys(&perCard))
			sc.Close()
			sc, err = cd.OpenSecureChannel(&perCard, rnd)
			must(err)
			identity, err := card.IdentityPart(account, tag, programID, uint32(counter))
			must(err)
			must(sc.Personalize(identity, issuerPub, cert))
			must(sc.ProvisionPINs(h["master_pin"], h["user_pin"]))
			sc.Close()
			p, err := cd.GetPersonalization()
			must(err)
			if !p.Personalized() || !p.PinProvisioned() || p.Flags&card.FlagSCP03KeysDefault != 0 {
				t.Errorf("read-back flags %02x", p.Flags)
			}
			if r.Consumed() != 17 || len(r.Failures()) != 0 {
				t.Errorf("consumed %d of %d: %v", r.Consumed(), len(rec.Exchanges), r.Failures())
			}
		})
	}
}
