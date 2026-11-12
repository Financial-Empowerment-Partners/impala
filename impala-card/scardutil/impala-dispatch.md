# Test Sequence: Impala applet 0.3 plaintext dispatch

Compatibility checks that every card OS running the Impala CAP must answer
identically. Plaintext commands only (no PIN, no SCP03, no personalization),
so the same file runs on a physical card, where it installs, checks and
removes the applet, and on the simulator target (`scripts/vpcd-sim.sh`),
where the CAP steps are skipped. A card that answers differently is a
compatibility finding for `docs/physical-evidence/`, not a test bug.

Expected status words were observed on applet 0.3 under jcardsim and agree
with `docs/apdu.md`, with two refinements the table does not spell out:
`SIGN_AUTH` on a blank card answers `6234` (the personalization guard runs
before the key guard), and `8430`/`8434` answer `6985` because a secured CLA
without an open SCP03 session fails the channel check before the per-INS
CLA rule (`6E00`) is reached. `GET_PERSONALIZATION` on a plain install starts
`00 08`: state blank, flags = SCP03 keys default. (Prose lines here must not begin with a
sequence verb such as install, select, send or the one that removes applets:
the Markdown parser would read them as steps.)

The Stellar key (applet 0.3, `docs/sep10-card-keys.md`) is made at INITIALIZE.
Before it, `GET_STELLAR_KEY` (`37`) answers `623C` and `SIGN_SEP10` (`38`)
answers `6234`. After it, `GET_PERSONALIZATION` starts `01 89` (initialized,
SCP03 keys default, flag `80` = Stellar key) and `GET_STELLAR_KEY` answers
`9000`. Those two post-INITIALIZE answers are the fleet's Ed25519 check: the
default CAP derives the public key through the card's own ECDH on a custom
curve, so a card OS whose ECDH refuses custom parameters answers `01 09` and
`623C` instead. That card is not broken: it runs as a legacy card
(`SIGN_AUTH` only), and the finding says which CAP it can take. The same two
answers are by design for `ImpalaApplet-none.cap`, and for
`ImpalaApplet-native.cap` on a JavaCard 3.1 card without pure EdDSA.
`SIGN_SEP10` stays at `6234` here because signing needs a personalized card,
which is the issuance tool's ground; the dispatch checks the key, not a
signature. The same sequence passes on the simulator's two hardware classes
(`impala-sim-jc305.cfg`, the default CAP on a JavaCard 3.0.5 card, and
`impala-sim-jc32.cfg`, the native CAP on a JavaCard 3.2 card); what tells
them apart is the first data byte of step 20, the engine that made the key:
`01` for the software engine, `02` for the platform's EdDSA.

Target applet `01020304050607080102`

1. Delete `0102030405060708` with deps (if present)
2. Install `ImpalaApplet.cap` as `01020304050607080102`
3. Send APDU `0064000000` expect `9000` data `00000003`
4. Send APDU `0034000000` expect `9000` data `0008`
5. Send APDU `0024000000` expect `6230`
6. Send APDU `00250000080102030405060708` expect `6234`
7. Send APDU `0037000000` expect `623C`
8. Send APDU `0038000000` expect `6234`
9. Send APDU `0006000000` expect `6D00`
10. Send APDU `0014000000` expect `6D00`
11. Send APDU `8030000000` expect `6D00`
12. Send APDU `8430000000` expect `6985`
13. Send APDU `8434000000` expect `6985`
14. Send APDU `002C00000400112233` expect `9000`
15. Send APDU `002C00000400112233` expect `6686`
16. Send APDU `0024000000` expect `9000`
17. Send APDU `001E000000` expect `9000`
18. Send APDU `00250000080102030405060708` expect `6234`
19. Send APDU `0034000000` expect `9000` data `0189`
20. Send APDU `0037000000` expect `9000`
21. Send APDU `0038000000` expect `6234`
22. Send APDU `0035000000` expect `9000`
23. Send APDU `0036000000` expect `6A83`
24. Delete `0102030405060708` with deps
