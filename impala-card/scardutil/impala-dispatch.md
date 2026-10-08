# Test Sequence: Impala applet 0.2 plaintext dispatch

Compatibility checks that every card OS running the Impala CAP must answer
identically. Plaintext commands only (no PIN, no SCP03, no personalization),
so the same file runs on a physical card, where it installs, checks and
removes the applet, and on the simulator target (`scripts/vpcd-sim.sh`),
where the CAP steps are skipped. A card that answers differently is a
compatibility finding for `docs/physical-evidence/`, not a test bug.

Expected status words were observed on applet 0.2 under jcardsim and agree
with `docs/apdu.md`, with two refinements the table does not spell out:
`SIGN_AUTH` on a blank card answers `6234` (the personalization guard runs
before the key guard), and `8430`/`8434` answer `6985` because a secured CLA
without an open SCP03 session fails the channel check before the per-INS
CLA rule (`6E00`) is reached. `GET_PERSONALIZATION` on a plain install starts
`00 08`: state blank, flags = SCP03 keys default. (Prose lines here must not begin with a
sequence verb such as install, select, send or the one that removes applets:
the Markdown parser would read them as steps.)

Target applet `01020304050607080102`

1. Delete `0102030405060708` with deps (if present)
2. Install `ImpalaApplet.cap` as `01020304050607080102`
3. Send APDU `0064000000` expect `9000` data `00000002`
4. Send APDU `0034000000` expect `9000` data `0008`
5. Send APDU `0024000000` expect `6230`
6. Send APDU `00250000080102030405060708` expect `6234`
7. Send APDU `0006000000` expect `6D00`
8. Send APDU `0014000000` expect `6D00`
9. Send APDU `8030000000` expect `6D00`
10. Send APDU `8430000000` expect `6985`
11. Send APDU `8434000000` expect `6985`
12. Send APDU `002C00000400112233` expect `9000`
13. Send APDU `002C00000400112233` expect `6686`
14. Send APDU `0024000000` expect `9000`
15. Send APDU `001E000000` expect `9000`
16. Send APDU `00250000080102030405060708` expect `6234`
17. Send APDU `0035000000` expect `9000`
18. Send APDU `0036000000` expect `6A83`
19. Delete `0102030405060708` with deps
