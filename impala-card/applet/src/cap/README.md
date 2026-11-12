# CAP-only sources

One `Ed25519Provider.java` per value of the `applet.ed25519` build option.
`build.xml` (`stageSources`) copies the applet sources to `build/cap-src`,
drops the simulator's provider and the engine the variant does not use, and
adds the provider from the matching directory here. Gradle's JVM source sets
never see these files; the simulator uses
`src/jvmMain/java/com/impala/applet/Ed25519Provider.java`, which holds every
engine and picks one at run time.

| Variant | Engine | JavaCard target | CAP |
|---|---|---|---|
| `soft` (default) | `Ed25519Soft` | 3.0.5 | `build/ImpalaApplet.cap` |
| `native` | `Ed25519Native` | 3.1.0 | `build/ImpalaApplet-native.cap` |
| `none` | none (legacy card) | 3.0.5 | `build/ImpalaApplet-none.cap` |
