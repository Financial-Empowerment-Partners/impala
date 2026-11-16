package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"impalactl/internal/card"
	"impalactl/internal/card/cardtest"
	"impalactl/internal/config"
)

// Known-answer replays: `card setup` against four sessions recorded between
// the reference issuance tool (Kotlin SDK) and the real applet 0.4 on
// jcardsim. The replay card requires every command to equal the next
// recorded one byte for byte, so these pin the SCP03 channel, the per-card
// key derivation, every payload layout and the command order against an
// implementation that shares no code with this one.
func TestCardSetupReplaysTheRecordedSessions(t *testing.T) {
	for _, name := range []string{
		"issuance-jc305-soft.txt", "issuance-jc305-soft-rerun.txt",
		"issuance-jc32-native.txt", "issuance-jc32-native-rerun.txt",
	} {
		t.Run(name, func(t *testing.T) {
			rec, err := cardtest.LoadRecording("../card/testdata/" + name)
			if err != nil {
				t.Fatal(err)
			}
			h := rec.Header
			rerun := strings.HasSuffix(name, "-rerun.txt")
			final := rec.LastAnswer([]byte{0x00, 0x34})
			cert, err := card.TrimDER(final[87:159])
			if err != nil {
				t.Fatal(err)
			}

			b := newIssueBridge(t)
			b.issuer, b.issuerHex = nil, hex.EncodeToString(final[22:87])
			b.programID, b.fixedCert = final[2:18], cert
			if rerun {
				// The holder registered the card when it was issued.
				userData := rec.LastAnswer([]byte{0x00, 0x1E})
				b.cards[hex.EncodeToString(userData[16:32])] = &issuedCard{
					account: h["account"], ecPub: hex.EncodeToString(rec.LastAnswer([]byte{0x00, 0x24})),
					cert: hex.EncodeToString(cert),
				}
			}
			r := cardtest.NewReplay(rec)
			spec := r.Start(t)
			hs := newHarness(t, "", b.handler())
			rnd := bytes.NewReader(rec.Randomness())
			hs.app.rand = rnd
			hs.env[config.EnvIssueKMK] = h["kmk"]
			hs.env[config.EnvCardPIN] = h["user_pin"]
			hs.env[config.EnvCardMasterPIN] = h["master_pin"]
			hs.env[config.EnvToken] = b.operator
			hs.env[config.EnvHolderToken] = b.holder

			code := hs.run("card", "setup", "--card", spec, "--account", h["account"], "--currency", h["currency"],
				"--initial-counter", h["initial_counter"], "--json")
			if fails := r.Failures(); len(fails) > 0 {
				t.Fatalf("the card saw a different command sequence:\n%s\nstderr:\n%s", strings.Join(fails, "\n"), hs.stderr())
			}
			if code != 0 {
				t.Fatalf("exit = %d:\n%s", code, hs.stderr())
			}
			if r.Consumed() != len(rec.Exchanges) {
				t.Errorf("consumed %d of %d recorded exchanges", r.Consumed(), len(rec.Exchanges))
			}
			if rnd.Len() != 0 {
				t.Errorf("%d bytes of the recorded randomness were not drawn", rnd.Len())
			}
			var got map[string]any
			if err := json.Unmarshal(hs.out.Bytes(), &got); err != nil {
				t.Fatalf("json: %v\n%s", err, hs.stdout())
			}
			for field, key := range map[string]string{
				"card_id": "record.card_id", "account_id": "record.account_uuid", "program_id": "record.program_id",
				"currency": "record.currency", "cert_id": "record.cert_id", "status": "record.status",
			} {
				if got[field] != h[key] {
					t.Errorf("%s = %v, recorded %s", field, got[field], h[key])
				}
			}
			if applet := got["applet"].(string) + "+" + got["applet_hash"].(string); applet != h["record.applet_version"] {
				t.Errorf("applet %s, recorded %s", applet, h["record.applet_version"])
			}
			sk, _ := got["stellar_key"].(map[string]any)
			if sk == nil || sk["address"] != h["record.stellar_address"] || sk["registered"] != true {
				t.Errorf("stellar_key = %v, recorded %s", got["stellar_key"], h["record.stellar_address"])
			}
			if _, ok := got["issuer_version"]; ok == rerun {
				t.Errorf("issuer_version present=%v on rerun=%v", ok, rerun)
			}
			if b.card(h["record.card_id"]).stellar != h["record.stellar_address"] {
				t.Error("the bridge did not register the Stellar key")
			}
			if n := b.called("POST /admin/cards/"); (n == 0) != rerun {
				t.Errorf("certifications: %d on rerun=%v", n, rerun)
			}
			noSecretsIn(t, hs, h["kmk"], h["user_pin"], h["master_pin"], b.operator, b.holder)
		})
	}
}

// noSecretsIn fails when a secret reaches stdout or stderr. PINs are matched
// as whole numbers (a PIN's digits may well occur inside a hex identifier).
func noSecretsIn(t *testing.T, h *harness, secrets ...string) {
	t.Helper()
	all := h.stdout() + "\n" + h.stderr()
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if len(s) <= 8 && isDigits(s) {
			for i := strings.Index(all, s); i >= 0; {
				before, after := byte(' '), byte(' ')
				if i > 0 {
					before = all[i-1]
				}
				if i+len(s) < len(all) {
					after = all[i+len(s)]
				}
				if !isHexByte(before) && !isHexByte(after) {
					t.Errorf("the secret %q appears in the output:\n%s", s, all)
					break
				}
				next := strings.Index(all[i+1:], s)
				if next < 0 {
					break
				}
				i += 1 + next
			}
			continue
		}
		if strings.Contains(strings.ToLower(all), strings.ToLower(s)) {
			t.Errorf("a secret appears in the output:\n%s", all)
		}
	}
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
