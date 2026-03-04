# CAPRunner Integration for ImpalaApplet

Tooling for inspecting compiled CAP files and running APDU tests against an emulated JavaCard environment, without requiring a physical smart card.

Built on [benallard/caprunner](https://github.com/benallard/caprunner), a Python-based CAP file parser and JavaCard bytecode emulator.

## Setup

Run the one-time setup script:

```bash
cd caprunner
./setup.sh
```

This will:
- Create a Python 3 virtual environment (`.venv/`)
- Clone `caprunner`, `pythoncard`, and `pythonplatform` into `vendor/`
- Symlink required modules
- Generate JavaCard reference files from SDK export files

## Inspecting CAP Files

View the internal structure of a compiled CAP file:

```bash
# Inspect the default ImpalaApplet.cap
./inspect.sh

# Inspect a specific CAP file
./inspect.sh /path/to/other.cap

# Pretty-printed inspection via captest.py
python captest.py inspect
python captest.py inspect /path/to/other.cap
```

Displays: Header, Directory, Applet info, Imports, ConstantPool, Classes, Methods, StaticFields, Descriptors, and Debug info.

## Running APDU Tests

Run a test script against the emulated applet:

```bash
# Run basic lifecycle tests
./test.sh scripts/test_basic.txt

# Run with a specific JavaCard version
./test.sh scripts/test_basic.txt 3.0.1

# Via captest.py (with colored output)
python captest.py test scripts/test_basic.txt
```

### Available Test Scripts

| Script | Description |
|--------|-------------|
| `scripts/test_basic.txt` | NOP, Is Card Alive, Get Version |
| `scripts/test_initialize.txt` | Initialize with random seed, Get EC Public Key |
| `scripts/test_pin.txt` | Initialize, Verify master PIN, Verify user PIN |

### Writing Custom Test Scripts

Generate a template:

```bash
python captest.py generate-script --name test_my_feature
```

#### Test Script Format

```
-- Comments start with double dash
load: ../applet/build/ImpalaApplet.cap
install: 0b 01 02 03 04 05 06 07 08 01 02 00 00 00 : 00

-- Select the applet
==> 00 A4 04 00 0A 01 02 03 04 05 06 07 08 01 02
<== 90 00

-- Send APDU: CLA INS P1 P2 [Lc] [Data...]
==> 00 02 00 00 00
-- Expected response: [Data...] SW1 SW2
<== 90 00
```

Directives:
- `load: <path>` — Load a CAP file into the emulator
- `install: <data> : <offset>` — Install the applet with given install parameters
- `==> <hex bytes>` — Send an APDU command
- `<== <hex bytes>` — Expected response (test fails if mismatch)
- `-- <text>` — Comment (ignored)
- `log;` — Print VM execution log

## Gradle Integration

From the project root:

```bash
# Setup CAPRunner
gradle caprunnerSetup

# Build and inspect the CAP file
gradle inspectCap

# Build and run all APDU tests
gradle caprunnerTest
```

## Known Limitations

- **JavaCard version**: CAPRunner was designed for JavaCard Classic up to ~3.0.1. The ImpalaApplet targets JC 3.0.5.
- **Crypto support**: CAP inspection works reliably for all versions. APDU execution works for basic commands (NOP, Is Card Alive, PIN verification), but commands depending on advanced cryptographic operations (ECDSA-SHA256, secp256r1) may fail in emulation.
- **Reference files**: The `genref.py` tool generates reference files from SDK export files. If you encounter import resolution errors, ensure the correct SDK version's export files are available.
