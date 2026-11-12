# jcardsim-jc31

jcardsim 3.0.6.0 turned into **simulated card hardware**: the JavaCard 3.0.5
simulator, the slice of the JavaCard 3.1 and 3.2 API that Ed25519 needs, and
a model of what a given card product does and does not have. With it the
applet is compiled and **run** in the JVM lanes as it would run on a JavaCard
3.0.5 card, on a 3.1 card and on a 3.2 card, including the cards that lack one
of the optional pieces. Test infrastructure only: it is never part of a CAP
file and never on an app's runtime classpath.

(The module keeps its first name. It began as the JavaCard 3.1 EdDSA layer.)

## Why a hardware model

jcardsim on its own is one card: JavaCard 3.0.5, every algorithm present, no
limit on memory. Real cards differ in exactly the places the Impala applet
depends on (`../README.md`, "Platform dependencies"):

- whether the platform has EdDSA at all (JavaCard 3.1 and later, optional);
- under which constants it offers it: the generic `SIG_CIPHER_EDDSA` of 3.1
  with `MessageDigest.ALG_NULL` or `ALG_SHA_512`, or the per-curve
  `SIG_CIPHER_EDDSA_ED25519` that 3.2 adds;
- on a JavaCard 3.0.5 card, whether the primitives of the software Ed25519
  engine are there: ECDH that returns both coordinates, custom curve
  parameters, SHA-512, a 256-bit AES key object, enough transient memory;
- which CAP the card loads in the first place (a CAP converted for JavaCard
  3.1 does not load on a 3.0.5 card).

A `CardPlatform` (`com.impala.jcardsim.jc31`) says which of those one simulated
card has, and the patched jcardsim classes ask it before they answer the
applet. The applet then meets what it would meet on such a card: an algorithm
that is not there, a curve the card will not compute on, no memory left.

## The card models

`CardPlatform.presets()`; the names are what every integration takes
(`SimulatorBibo(platform = …)`, `:simulator:serve --platform`, `impala.platform`
in a vpcd cfg, `DEMO_CARD_PLATFORM` in the demo kit).

| Name | Level | What it is | Default CAP → card | Native CAP → card |
|---|---|---|---|---|
| `jc305` | 3.0.5 | Everything the software engine needs; no EdDSA API | Stellar key (soft) | does not load |
| `jc305-no-xy` | 3.0.5 | No `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` | legacy card | does not load |
| `jc305-fixed-curves` | 3.0.5 | Refuses curve parameters other than its own curves | legacy card | does not load |
| `jc305-wrong-curve-math` | 3.0.5 | Accepts custom parameters and computes on them wrongly, consistently | legacy card | does not load |
| `jc305-no-sha512` | 3.0.5 | No `MessageDigest.ALG_SHA_512` | legacy card | does not load |
| `jc305-no-aes256` | 3.0.5 | No 256-bit AES key objects | legacy card | does not load |
| `jc305-small-ram` | 3.0.5 | 512 bytes of deselect-transient memory: the engine's work area does not fit | legacy card | does not load |
| `jc305-tight-ram` | 3.0.5 | 1024 bytes: the engine fits, the SEP-10 challenge stage does not | legacy card | does not load |
| `jc31` | 3.1 | EdDSA as `SIG_CIPHER_EDDSA` with `ALG_NULL` | Stellar key (soft) | Stellar key (native) |
| `jc31-sha512` | 3.1 | EdDSA as `SIG_CIPHER_EDDSA` with `ALG_SHA_512` only | Stellar key (soft) | Stellar key (native) |
| `jc32` | 3.2 | EdDSA as `SIG_CIPHER_EDDSA` and as `SIG_CIPHER_EDDSA_ED25519` | Stellar key (soft) | Stellar key (native) |
| `jc32-per-curve` | 3.2 | Ed25519 only as `SIG_CIPHER_EDDSA_ED25519` | Stellar key (soft) | Stellar key (native) |
| `jc32-no-eddsa` | 3.2 | No EdDSA (it is optional at every level) | Stellar key (soft) | legacy card |
| `jc32-no-key-import` | 3.2 | Generates Ed25519 keys, refuses to load a private one | Stellar key (soft) | legacy card |

The two right-hand columns are the contract, pinned by
`sdk/src/jvmTest/.../CardHardwareInteropTest.kt` on the real applet. "Legacy
card" means the applet installed and works without a Stellar key (flag `0x80`
clear, `GET_STELLAR_KEY` answers `0x623C`, `SIGN_AUTH` and transfers work).
The 3.1 and 3.2 models also have everything `jc305` has, so the default CAP
runs on them. A model for a case that is not listed is one `CardPlatform`
builder call:

```kotlin
val card = CardPlatform.JC32.toBuilder("jc32-1k").transientMemory(-1, 1024).build()
```

Nothing here models a named product. Which real cards behave like which model
is what fleet testing on hardware finds out (`../scardutil/README.md`).

### What a model decides

| Property | Simulated by |
|---|---|
| JavaCard level (3.0.5 / 3.1 / 3.2) and the API package versions it exports | `CardPlatform.Level`; `:simulator`'s `CapVariant.loadsOn` refuses a CAP that imports later versions |
| EdDSA requests accepted: `(ALG_NULL, SIG_CIPHER_EDDSA)`, `(ALG_SHA_512, SIG_CIPHER_EDDSA)`, `(ALG_NULL, SIG_CIPHER_EDDSA_ED25519)` | `Signature.getInstance(byte, byte, byte, boolean)`; `KeyBuilder.buildXECKey` and `NamedParameterSpec.getInstance` exist only where one is accepted |
| Whether that EdDSA is pure Ed25519 when it signs and when it verifies | the signature instance hashes the message first where the model says so (builder only: `edDsaNotPure`) |
| Loading an Ed25519 private key | `XECPrivateKey.setEncoded` (`ILLEGAL_USE` where refused; key generation always works) |
| `ALG_EC_SVDP_DH_PLAIN_XY` | `KeyAgreement.getInstance` |
| Custom curve parameters: computed, refused, or computed wrongly | the key agreement and `KeyPair.genKeyPair()`; "wrongly" returns the negative of the right point from both, so the card agrees with itself and only a known-answer test can tell |
| SHA-512 | `MessageDigest.getInstance` |
| 256-bit AES key objects | `KeyBuilder.buildKey` |
| Transient memory, per clearing event | `JCSystem.makeTransient*Array`: `SystemException.NO_TRANSIENT_SPACE` when the card's budget is used up |

Not simulated, on any model: transient EC private keys (jcardsim has none, so
the software engine always runs its persistent fallback here), pre-hash EdDSA
and Ed448 (`NO_SUCH_ALGORITHM`), timing, and anything specific to a product.

## Using it

A card's platform is chosen where the card is made. `:simulator` does it for
every integration:

```kotlin
SimulatorBibo(platform = CardPlatform.JC305)                 // default CAP on a JavaCard 3.0.5 card
SimulatorBibo(platform = CardPlatform.JC32)                  // native CAP on a JavaCard 3.2 card
SimulatorBibo(ed25519 = "soft", platform = CardPlatform.JC32) // the default CAP on JavaCard 3.2 hardware
SimulatorBibo(ed25519 = "native", platform = CardPlatform.JC305) // throws CapNotLoadableException
```

Underneath, a platform makes cards and a card runs code:

```kotlin
val card = CardPlatform.JC305_NO_XY.newCard()
card.execute { /* applet install, a command: API calls are answered for this card */ }
card.transientDeselectBytesUsed()
```

The objects created inside (a key agreement, a key pair, a signature, a key)
remember their card, so what happens to them later needs no scope. Code that
runs outside any card, such as a unit test that builds an engine directly,
gets a platform with everything present, no memory limit and the JavaCard 3.1
EdDSA API in the flavour of the system property `jcardsim.jc31.eddsa`, read on
every call:

| Value | Platform |
|---|---|
| `any` (default) | pure Ed25519 under both `MessageDigest.ALG_NULL` and `ALG_SHA_512` |
| `null` / `sha512` | pure Ed25519 under that message digest constant only |
| `not-pure` | accepts both constants but signs a pre-hashed message: not pure Ed25519 |
| `sign-not-pure` | verifies pure Ed25519 but signs a pre-hashed message: the two directions disagree |
| `none` | no Ed25519 |

That default never offers the JavaCard 3.2 constant; only a card whose
platform has it does.

## What it adds to jcardsim, and how it is built

jcardsim's `javacard.*` classes are generated when jcardsim itself is built,
so they cannot be overridden from source, and two jars with the same class
names on one classpath would be resolved by order. This module therefore
**replaces** the `com.klinec:jcardsim` dependency:

1. `patchJcardsim` (`src/patcher`, ASM) unpacks the jcardsim jar and patches
   its API classes. Everything else is copied byte for byte. The patcher
   fails, rather than guess, if a class does not look the way it expects (for
   example after a jcardsim upgrade).
2. The sources in `src/main` are compiled against the patched classes.
3. The jar holds both. Consumers always get the jar, never a bare classes
   directory.

| JavaCard API | Here |
|---|---|
| 3.1: `NamedParameterSpec` (`ED25519` only; the other names answer `NO_SUCH_ALGORITHM`), `AlgorithmParameterSpec`, `XECKey`, `XECPublicKey`, `XECPrivateKey` | source, `src/main/java/javacard/security`; keys hold the RFC 8032 encodings in persistent or transient card memory |
| 3.1: `KeyBuilder.buildXECKey`, `TYPE_XEC`, `ATTR_PUBLIC`, `ATTR_PRIVATE` | added to jcardsim's `KeyBuilder` by the patcher |
| 3.1: `Signature.SIG_CIPHER_EDDSA`, `SIG_CIPHER_EDDSAPH`; 3.2: `SIG_CIPHER_EDDSA_ED25519`, `SIG_CIPHER_EDDSA_ED448`, `SIG_CIPHER_EDDSAPH_ED25519`, `SIG_CIPHER_EDDSAPH_ED448` | constants added by the patcher (values 13 to 18, as in the API jars of the vendored kits) |
| `KeyPair(PublicKey, PrivateKey)` over XEC keys, `genKeyPair(AlgorithmParameterSpec)` | source; jcardsim's own `KeyPair` logic is kept for every other key type |
| Static factories that depend on the card: `Signature.getInstance(byte, byte, byte, boolean)`, `KeyAgreement.getInstance`, `MessageDigest.getInstance`, `KeyBuilder.buildKey(byte, short, boolean)`, `JCSystem.makeTransientByteArray` / `ShortArray` / `BooleanArray` / `ObjectArray` | the original is kept as `jcardsim<Name>`; the method of the original name calls a hook in `Jc31`, which asks the card's platform and then falls through |

The Ed25519 itself is the JDK's (15+), an implementation independent of the
applet's own (`Ed25519Soft`), which is what makes it useful as a second
opinion.

`:applet`, `:simulator` and the SDK tests depend on `project(":jcardsim-jc31")`;
nothing else may depend on `com.klinec:jcardsim` directly.

## Tests

- `applet/src/jvmTest/.../Jc31LayerTest.kt`: RFC 8032 vectors through the
  JavaCard API, misuse, the EdDSA profiles, and that jcardsim's own algorithms
  are still reached.
- `applet/src/jvmTest/.../CardPlatformTest.kt`: the model (levels, presets,
  each optional algorithm switched off on its own, the two custom-curve
  failures, the memory budget) and both Ed25519 engines on each card model.
- `sdk/src/jvmTest/.../CardHardwareInteropTest.kt`: the real applet, every
  CAP on every card model, and the memory it takes.
- `simulator/src/jvmTest/.../CardHardwareSimulatorTest.kt`: the hardware
  options of the TCP server and the vpcd simulator, and the CAP files against
  `CapVariant`.

## Licence

jcardsim is Apache-2.0; its `LICENSE` and `NOTICE` are carried in the jar under
`META-INF/`. The changes made to it are the ones listed above.
