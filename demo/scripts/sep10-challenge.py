#!/usr/bin/env python3
"""Read a SEP-10 challenge without any Stellar library and print what it says, as JSON.

Usage: sep10-challenge.py <base64 transaction envelope>      (or the envelope on stdin)

The demo uses it to look at a challenge with code that shares nothing with the bridge, the card or the
app: plain XDR, read field by field. It reports; it does not judge (the scenarios assert on the JSON).
It accepts exactly the shape SEP-10 defines (a v1 envelope, ed25519 accounts, time bounds, no memo,
manage-data operations) and exits 1 with a reason for anything else. Signatures are counted and their
hints shown, not verified: verification is the card's client's job (Sep10Challenge.verify) and the server's.
Python 3 standard library only.
"""
import base64
import binascii
import json
import struct
import sys

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def crc16_xmodem(data):
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def account_id(key32):
    """G... strkey of a 32-byte ed25519 public key."""
    payload = bytes([6 << 3]) + key32
    payload += struct.pack("<H", crc16_xmodem(payload))
    bits = "".join(format(b, "08b") for b in payload)
    return "".join(ALPHABET[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        if self.pos + n > len(self.data):
            raise ValueError("truncated at byte %d" % self.pos)
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def u64(self):
        return struct.unpack(">Q", self.take(8))[0]

    def i64(self):
        return struct.unpack(">q", self.take(8))[0]

    def opaque(self, maximum):
        n = self.u32()
        if n > maximum:
            raise ValueError("length %d above %d at byte %d" % (n, maximum, self.pos))
        value = self.take(n)
        pad = self.take((4 - n % 4) % 4)
        if any(pad):
            raise ValueError("non-zero padding at byte %d" % self.pos)
        return value

    def account(self):
        if self.u32() != 0:
            raise ValueError("not an ed25519 account at byte %d (muxed accounts are not SEP-10 challenge sources here)" % self.pos)
        return account_id(self.take(32))


def describe(envelope_b64):
    try:
        r = Reader(base64.b64decode(envelope_b64, validate=True))
    except (binascii.Error, ValueError) as e:
        raise ValueError("not base64: %s" % e)
    if r.u32() != 2:
        raise ValueError("not a v1 transaction envelope (ENVELOPE_TYPE_TX)")
    out = {"source": r.account(), "fee": r.u32(), "sequence": r.i64()}
    if r.u32() != 1:
        raise ValueError("preconditions are not PRECOND_TIME")
    out["min_time"], out["max_time"] = r.u64(), r.u64()
    out["lifetime_secs"] = out["max_time"] - out["min_time"]
    if r.u32() != 0:
        raise ValueError("the transaction has a memo")
    ops = []
    for _ in range(r.u32()):
        op = {"source": r.account() if r.u32() == 1 else None}
        op_type = r.u32()
        if op_type != 10:
            raise ValueError("operation type %d is not MANAGE_DATA" % op_type)
        op["name"] = r.opaque(64).decode("utf-8", "replace")
        if r.u32() == 1:
            value = r.opaque(64)
            op["value_bytes"] = len(value)
            # A challenge nonce is 64 base64 characters; a domain is text: both are printable.
            op["value"] = value.decode("ascii") if all(32 <= b < 127 for b in value) else None
        else:
            op["value_bytes"] = None
            op["value"] = None
        ops.append(op)
    out["operations"] = ops
    if r.u32() != 0:
        raise ValueError("the transaction has an extension")
    signatures = []
    for _ in range(r.u32()):
        hint = r.take(4)
        signatures.append({"hint": hint.hex(), "bytes": len(r.opaque(64))})
    out["signatures"] = signatures
    if r.pos != len(r.data):
        raise ValueError("%d trailing bytes" % (len(r.data) - r.pos))
    out["envelope_bytes"] = len(r.data)
    return out


def main():
    text = sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read()
    try:
        print(json.dumps(describe(text.strip())))
    except ValueError as e:
        print("sep10-challenge: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
