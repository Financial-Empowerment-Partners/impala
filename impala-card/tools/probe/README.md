# Capability probe

A diagnostic applet and its host program. They answer one question about a
physical card: which of the primitives behind the applet's Ed25519 engine
(`applet/.../Ed25519Soft.java`: SHA-512, a 256-bit AES key object, ECDH with
both coordinates on a custom curve, key generation on that curve) does the
card really have, and what does it answer where it has none.

The Impala applet only reports the outcome (no Stellar key: `GET_STELLAR_KEY`
answers `623C`). The probe asks for each primitive on its own, and counts one
as present only when the card's answer equals a value computed on the host.

```bash
cd impala-card
./gradlew :tools:probe:test            # the probe on simulated card models
./gradlew :tools:probe:buildProbeCap   # tools/probe/build/ImpalaProbe.cap (JDK 17)

# On a card (GlobalPlatform keys needed to load and to remove it):
java -jar applet/libs/gp-v25.10.20.jar --install tools/probe/build/ImpalaProbe.cap
./gradlew :tools:probe:run [--args="<reader name>"]
java -jar applet/libs/gp-v25.10.20.jar --uninstall tools/probe/build/ImpalaProbe.cap
```

- The probe has its own AID (`F0494D5050524F4245`, applet `…01`): it sits next
  to an installed Impala applet and touches nothing of it.
- It holds no secret and keeps no state. The scalars, the AES key and the RSA
  modulus it computes with are fixed test values sent by the host. The one key
  it generates on the card is discarded in the same command.
- The CAP is converted for JavaCard 3.0.1, so it loads wherever the legacy CAP
  loads; newer algorithms are asked for by number at run time.
- Each probe builds its own key objects. On a card without object deletion
  that memory comes back only when the probe is uninstalled, so uninstall it
  after the run.

The report ends with a verdict: every primitive present; only parts that
applet code can replace are missing (SHA-512, or the second coordinate of the
ECDH result); or no usable ECDH on the curve at all, with whether raw RSA is
there as a modular multiplier and how long one 256-bit multiplication takes in
bytecode on that card.
