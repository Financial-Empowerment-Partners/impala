# Recorded issuance sessions

`issuance-*.txt` are card sessions recorded off the wire: the reference issuance tool
(`impala-card/tools/issue`, on the Kotlin card SDK) setting up the real `ImpalaApplet` on jcardsim,
captured by a logging proxy on the simulator's TCP framing. Each file's header says what it is.

| File | Card | Session |
|---|---|---|
| `issuance-jc305-soft.txt` | a JavaCard 3.0.5 card, the default CAP (software Ed25519) | the whole ceremony on a blank card, XLM |
| `issuance-jc305-soft-rerun.txt` | the same card | the second run: read-only, `already-issued` |
| `issuance-jc32-native.txt` | a JavaCard 3.2 card, the native CAP (platform EdDSA) | the whole ceremony, USDC, receive-counter floor 7 |
| `issuance-jc32-native-rerun.txt` | the same card | the second run |

They are known-answer vectors for `impalactl card setup`, which is a Go port of that tool:

- `internal/card` replays the two full sessions through its own SCP03 channel and card commands
  (`scp03_replay_test.go`): key derivation, cryptograms, C-MAC chaining, the counter ICV, padding and every
  payload must come out as recorded.
- `internal/cli` runs the real command against a replaying card and a stub bridge that serves the recorded
  issuer key, program id and certificate. Every command must equal the next recorded one, byte for byte and
  in order, and the record must be the one the reference tool printed.

So a difference between the two tools in a step, a payload or their order fails here. The randomness of a
session (the `INITIALIZE` seed, the SCP03 host challenges) is read back from the recording.

Everything in these files is test material: a throwaway key master key, PINs, account and issuer
(`--test-issuer`), and a simulated card's public keys. Nothing here is, or was derived from, a secret of
any deployment.

## Recording them again

When the ceremony changes (in both tools), or the applet's version does (every session starts with the
card's `GET_VERSION` answer):

```bash
internal/card/testdata/record.sh        # needs JDK 17 and python3; about a minute
go test ./...
```

`record.sh` starts a simulated card of each class on a scratch port, runs the reference tool twice through
`record_proxy.py`, and rewrites the four files. Card keys and challenges are random, so every recording is
new bytes; commit them together.
