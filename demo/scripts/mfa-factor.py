#!/usr/bin/env python3
"""Demo-side MFA factor helpers (stdlib only), for scenario-14-mfa.sh.

Two subcommands, matching the bridge's contract
(docs/mfa-card-pin-biometrics.md):

  totp <base32-secret> [unix_time]
      Print the current 6-digit TOTP code (HMAC-SHA1, 30 s step), the same
      algorithm `impala_mfa` enrols and the bridge verifies.

  device-message <account_id> <purpose-int> <challenge-hex>
      Write the device-key assertion message to stdout as RAW bytes:
      "IMPALA-DKEY:" || 0x01 || purpose || sha256(account_id utf-8) ||
      challenge(32). The scenario signs it with an openssl P-256 key and posts
      the hex signature; the bridge rebuilds and verifies the same bytes.

No third-party modules: the demo host is not guaranteed to have `cryptography`,
so the ECDSA itself is done with openssl in the shell; this only builds the
message and the TOTP code.
"""
import base64
import hashlib
import hmac
import struct
import sys
import time

DOMAIN_TAG = b"IMPALA-DKEY:"
VERSION = 0x01


def totp(secret_b32, when=None):
    # Pad the base32 secret (totp-rs emits unpadded) and decode.
    s = secret_b32.strip().upper()
    s += "=" * ((8 - len(s) % 8) % 8)
    key = base64.b32decode(s)
    counter = int((when if when is not None else time.time()) // 30)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return "%06d" % code


def device_message(account_id, purpose, challenge_hex):
    challenge = bytes.fromhex(challenge_hex)
    if len(challenge) != 32:
        raise SystemExit("challenge must be 32 bytes (64 hex chars)")
    account_hash = hashlib.sha256(account_id.encode("utf-8")).digest()
    return DOMAIN_TAG + bytes([VERSION, purpose & 0xFF]) + account_hash + challenge


def main(argv):
    if len(argv) < 2:
        raise SystemExit("usage: mfa-factor.py totp|device-message ...")
    cmd = argv[1]
    if cmd == "totp":
        when = float(argv[3]) if len(argv) > 3 else None
        sys.stdout.write(totp(argv[2], when))
    elif cmd == "device-message":
        if len(argv) != 5:
            raise SystemExit("usage: mfa-factor.py device-message <account_id> <purpose-int> <challenge-hex>")
        sys.stdout.buffer.write(device_message(argv[2], int(argv[3]), argv[4]))
    else:
        raise SystemExit("unknown subcommand: " + cmd)


if __name__ == "__main__":
    main(sys.argv)
