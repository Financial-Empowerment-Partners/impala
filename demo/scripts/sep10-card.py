#!/usr/bin/env python3
"""Talk to the simulated card's SEP-10 commands over the simulator's socket, and check what comes back.

The demo uses it to show the card's own rules with code that shares nothing with the card SDK, the app
or the bridge: the APDUs are written out by hand, the transactions are plain XDR, and the Ed25519 check
is the reference algorithm of RFC 8032. Python 3 standard library only.

  sep10-card.py key      [--port N]                 the card's Stellar key: engine, public key, address
  sep10-card.py tx       <envelope b64>             the Transaction bytes inside a v1 envelope (hex)
  sep10-card.py sign     (--envelope B64 | --tx HEX) --passphrase P [--port N]
                                                    SIGN_SEP10: the signature, or the status word of the refusal
  sep10-card.py finish   [--port N]                 a lone FINISH (nothing staged): the status word
  sep10-card.py verify   (--envelope B64 | --tx HEX) --passphrase P --public-key HEX --signature HEX
                                                    exit 0 when the signature is that key's over the transaction hash
  sep10-card.py attach   <envelope b64> --public-key HEX --signature HEX
                                                    the envelope with that signature appended (base64)
  sep10-card.py server-signed <envelope b64> --passphrase P
                                                    exit 0 when the envelope carries a valid signature of the
                                                    transaction's own source account (the SEP-10 server's key)
  sep10-card.py variant  sequence|trailing <envelope b64>
                                                    the same transaction with sequence number 1 / one more byte (hex)
  sep10-card.py variant  payment --source G --op-source G --destination G --stroops N [--challenge-shaped]
                                                    a one-operation payment (hex); --challenge-shaped gives it
                                                    sequence 0, as a challenge has (otherwise a real sequence number)
  sep10-card.py self-test                           RFC 8032 vectors through the verifier, strkey round trip

`sign` prints JSON on stdout and exits 0 whatever the card answered: a refusal is an answer, and the
scenarios assert on the status word. Transport and usage errors exit 1 with a reason on stderr.
"""
import argparse
import base64
import binascii
import hashlib
import json
import socket
import struct
import sys
import time

SELECT_APPLET = "00A404000A0102030405060708010200"
INS_GET_STELLAR_KEY = 0x37
INS_SIGN_SEP10 = 0x38
P1_BEGIN, P1_CONTINUE, P1_FINISH = 0x00, 0x01, 0x02
MAX_APDU_DATA = 255
ENGINES = {1: "soft", 2: "native"}
# docs/sep10-card-keys.md §3.3: the status word names the first rule a transaction broke.
MEANINGS = {
    "9000": "signed",
    "6240": "not the shape of a SEP-10 challenge (account type, memo, lengths, trailing bytes)",
    "6241": "the sequence number is not 0",
    "6242": "an operation is not MANAGE_DATA (or there are not 1 to 5 of them)",
    "6243": "wrong account: the transaction is sourced by this card's key, or its first operation is not",
    "6244": "the first operation is not a \"<domain> auth\" entry with a value",
    "6245": "no time bounds with an upper limit",
    "623c": "the card has no Stellar key",
    "6985": "nothing is staged (CONTINUE or FINISH without BEGIN)",
    "6700": "wrong length (BEGIN under 33 bytes, or a transaction over 640 bytes)",
    "6a86": "wrong P1/P2",
}

# ------------------------------------------------------------------------------------------ strkey
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
    return base64.b32encode(payload).decode("ascii")


def account_key(address):
    """The 32-byte ed25519 public key of a G... strkey (checksum verified)."""
    try:
        raw = base64.b32decode(address)
    except (binascii.Error, ValueError):
        raise ValueError("%r is not a Stellar account id" % address)
    if len(raw) != 35 or raw[0] != 6 << 3 or struct.unpack("<H", raw[33:])[0] != crc16_xmodem(raw[:33]):
        raise ValueError("%r is not a Stellar account id (version byte or checksum)" % address)
    return raw[1:33]


# ------------------------------------------------------------------------------------------ Ed25519 verification (RFC 8032, section 6)
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    D = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(scalar, point):
    out = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            out = _add(out, point)
        point = _add(point, point)
        scalar >>= 1
    return out


def _same(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_BY = 4 * pow(5, _P - 2, _P) % _P
_BX = _recover_x(_BY, 0)
_BASE = (_BX, _BY, 1, _BX * _BY % _P)


def _point(encoded):
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def ed25519_verify(public, message, signature):
    """True when `signature` (64 bytes) is `public`'s (32 bytes) pure-Ed25519 signature of `message`."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a, r = _point(public), _point(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    return _same(_mul(s, _BASE), _add(r, _mul(h, a)))


# ------------------------------------------------------------------------------------------ XDR: just enough of a transaction
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

    def opaque(self, maximum):
        n = self.u32()
        if n > maximum:
            raise ValueError("length %d above %d at byte %d" % (n, maximum, self.pos))
        value = self.take(n)
        if any(self.take((4 - n % 4) % 4)):
            raise ValueError("non-zero padding at byte %d" % self.pos)
        return value

    def account(self):
        if self.u32() != 0:
            raise ValueError("not an ed25519 account at byte %d" % self.pos)
        return self.take(32)


def split_envelope(envelope_b64):
    """(Transaction bytes, [(hint, signature), ...]) of a v1 envelope whose operations are manage-data or
    native payments: the two kinds this tool is ever handed. Anything else is refused by name."""
    try:
        r = Reader(base64.b64decode(envelope_b64, validate=True))
    except (binascii.Error, ValueError) as e:
        raise ValueError("not base64: %s" % e)
    if r.u32() != 2:
        raise ValueError("not a v1 transaction envelope (ENVELOPE_TYPE_TX)")
    start = r.pos
    r.account()
    r.take(4 + 8)  # fee, sequence number
    cond = r.u32()
    if cond == 1:
        r.take(16)
    elif cond != 0:
        raise ValueError("preconditions of type %d are not read by this tool" % cond)
    if r.u32() != 0:
        raise ValueError("the transaction has a memo")
    count = r.u32()
    if count > 100:
        raise ValueError("%d operations" % count)
    for _ in range(count):
        present = r.u32()
        if present == 1:
            r.account()
        elif present != 0:
            raise ValueError("bad optional flag at byte %d" % r.pos)
        kind = r.u32()
        if kind == 10:  # MANAGE_DATA
            r.opaque(64)
            has_value = r.u32()
            if has_value == 1:
                r.opaque(64)
            elif has_value != 0:
                raise ValueError("bad optional flag at byte %d" % r.pos)
        elif kind == 1:  # PAYMENT
            r.account()
            if r.u32() != 0:
                raise ValueError("only native-asset payments are read by this tool")
            r.take(8)
        else:
            raise ValueError("operation type %d is not read by this tool" % kind)
    if r.u32() != 0:
        raise ValueError("the transaction has an extension")
    tx = r.data[start:r.pos]
    signatures = []
    for _ in range(r.u32()):
        hint = r.take(4)
        signatures.append((hint, r.opaque(64)))
    if r.pos != len(r.data):
        raise ValueError("%d trailing bytes after the signatures" % (len(r.data) - r.pos))
    return tx, signatures


def envelope(tx, signatures):
    out = struct.pack(">I", 2) + tx + struct.pack(">I", len(signatures))
    for hint, sig in signatures:
        out += hint + struct.pack(">I", len(sig)) + sig + b"\x00" * ((4 - len(sig) % 4) % 4)
    return base64.b64encode(out).decode("ascii")


def transaction_hash(passphrase, tx):
    """What a Stellar signature signs: SHA-256(network id ‖ ENVELOPE_TYPE_TX ‖ Transaction)."""
    return hashlib.sha256(hashlib.sha256(passphrase.encode("utf-8")).digest() + struct.pack(">I", 2) + tx).digest()


def payment_tx(source, op_source, destination, stroops, challenge_shaped):
    """A one-operation native payment. With challenge_shaped it borrows a challenge's outside: sequence 0."""
    if stroops <= 0:
        raise ValueError("stroops must be a positive integer")
    now = int(time.time())
    sequence = 0 if challenge_shaped else 4242424242
    return (struct.pack(">I", 0) + source + struct.pack(">I", 100) + struct.pack(">q", sequence)
            + struct.pack(">IQQ", 1, now, now + 300)          # PRECOND_TIME
            + struct.pack(">I", 0)                            # MEMO_NONE
            + struct.pack(">I", 1)                            # one operation
            + struct.pack(">II", 1, 0) + op_source            # its source account
            + struct.pack(">I", 1)                            # PAYMENT
            + struct.pack(">I", 0) + destination              # destination
            + struct.pack(">I", 0)                            # native asset
            + struct.pack(">q", stroops)
            + struct.pack(">I", 0))                           # ext


# ------------------------------------------------------------------------------------------ the card
class Card:
    """One connection to the simulator: a 2-byte big-endian length, then the APDU; the answer the same way."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=30)
        self.count = 0
        data, sw = self.apdu(bytes.fromhex(SELECT_APPLET))
        if sw != "9000":
            raise RuntimeError("SELECT answered %s: no Impala applet on this card" % sw)

    def apdu(self, command):
        self.sock.sendall(struct.pack(">H", len(command)) + command)
        n = struct.unpack(">H", self._read(2))[0]
        answer = self._read(n)
        self.count += 1
        if len(answer) < 2:
            raise RuntimeError("short answer from the simulator")
        return answer[:-2], answer[-2:].hex()

    def _read(self, n):
        out = b""
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise RuntimeError("the simulator closed the connection")
            out += chunk
        return out

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def stellar_key(self):
        data, sw = self.apdu(bytes([0x00, INS_GET_STELLAR_KEY, 0x00, 0x00, 0x00]))
        if sw == "623c":
            return None
        if sw != "9000" or len(data) != 169:
            raise RuntimeError("GET_STELLAR_KEY answered %d bytes, SW %s" % (len(data), sw))
        return {"engine": ENGINES.get(data[0], "engine-%02x" % data[0]), "public_key": data[1:33].hex(),
                "address": account_id(data[1:33]), "personalized": any(data[33:])}

    def part(self, p1, data):
        return self.apdu(bytes([0x00, INS_SIGN_SEP10, p1, 0x00, len(data)]) + data)

    def sign_sep10(self, network_id, tx):
        """The SDK's chunking (ImpalaSDK.signSep10): BEGIN carries the network id and what fits beside it, but
        never the last byte; CONTINUE while more than one APDU is left; FINISH carries the rest and signs."""
        if len(tx) < 2:
            raise ValueError("a transaction is at least 2 bytes")
        sent = min(len(tx) - 1, MAX_APDU_DATA - len(network_id))
        data, sw = self.part(P1_BEGIN, network_id + tx[:sent])
        if sw != "9000":
            return "BEGIN", sw, None
        while len(tx) - sent > MAX_APDU_DATA:
            data, sw = self.part(P1_CONTINUE, tx[sent:sent + MAX_APDU_DATA])
            if sw != "9000":
                return "CONTINUE", sw, None
            sent += MAX_APDU_DATA
        data, sw = self.part(P1_FINISH, tx[sent:])
        return "FINISH", sw, (data if sw == "9000" else None)


def self_test():
    vectors = [  # RFC 8032 section 7.1, TEST 1 and TEST 2: public key, message, signature
        ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ]
    for public, message, signature in vectors:
        pk, msg, sig = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
        assert ed25519_verify(pk, msg, sig), "RFC 8032 vector does not verify"
        assert not ed25519_verify(pk, msg + b"x", sig), "a changed message verifies"
        assert not ed25519_verify(pk, msg, sig[:63] + bytes([sig[63] ^ 1])), "a changed signature verifies"
        assert account_key(account_id(pk)) == pk, "strkey round trip"
    # a payment is read back by the envelope reader, and its hash depends on the network
    key = bytes.fromhex(vectors[0][0])
    tx = payment_tx(key, key, bytes.fromhex(vectors[1][0]), 1000000000, False)
    assert split_envelope(envelope(tx, [])) == (tx, []), "envelope round trip"
    assert transaction_hash("Test SDF Network ; September 2015", tx) != transaction_hash("Public Global Stellar Network ; September 2015", tx)
    print("ok")


def main():
    ap = argparse.ArgumentParser(prog="sep10-card.py", description="the simulated card's SEP-10 commands, by hand")
    sub = ap.add_subparsers(dest="cmd")

    def with_port(p):
        p.add_argument("--port", type=int, default=9443)

    def with_tx(p):
        p.add_argument("--envelope")
        p.add_argument("--tx")
        p.add_argument("--passphrase", required=True)

    with_port(sub.add_parser("key"))
    sub.add_parser("tx").add_argument("envelope")
    p = sub.add_parser("sign"); with_tx(p); with_port(p)
    with_port(sub.add_parser("finish"))
    p = sub.add_parser("verify"); with_tx(p)
    p.add_argument("--public-key", required=True); p.add_argument("--signature", required=True)
    p = sub.add_parser("attach"); p.add_argument("envelope")
    p.add_argument("--public-key", required=True); p.add_argument("--signature", required=True)
    p = sub.add_parser("server-signed"); p.add_argument("envelope"); p.add_argument("--passphrase", required=True)
    p = sub.add_parser("variant"); p.add_argument("kind", choices=["sequence", "trailing", "payment"])
    p.add_argument("envelope", nargs="?")
    p.add_argument("--source"); p.add_argument("--op-source"); p.add_argument("--destination")
    p.add_argument("--stroops", type=int); p.add_argument("--challenge-shaped", action="store_true")
    sub.add_parser("self-test")
    a = ap.parse_args()

    def tx_of(args):
        if bool(args.envelope) == bool(args.tx):
            raise ValueError("give exactly one of --envelope and --tx")
        return split_envelope(args.envelope)[0] if args.envelope else bytes.fromhex(args.tx)

    try:
        if a.cmd == "key":
            card = Card(a.port)
            try:
                key = card.stellar_key()
            finally:
                card.close()
            print(json.dumps(key if key else {"engine": "none"}))
        elif a.cmd == "tx":
            print(split_envelope(a.envelope)[0].hex())
        elif a.cmd == "sign":
            tx = tx_of(a)
            card = Card(a.port)
            try:
                step, sw, signature = card.sign_sep10(hashlib.sha256(a.passphrase.encode("utf-8")).digest(), tx)
                apdus = card.count - 1  # without the SELECT
            finally:
                card.close()
            out = {"sw": sw, "step": step, "meaning": MEANINGS.get(sw, "status word %s" % sw), "tx_bytes": len(tx), "apdus": apdus}
            if signature is not None:
                out["signature"] = signature.hex()
                out["tx_hash"] = transaction_hash(a.passphrase, tx).hex()
            print(json.dumps(out))
        elif a.cmd == "finish":
            card = Card(a.port)
            try:
                data, sw = card.part(P1_FINISH, b"\x00")
            finally:
                card.close()
            print(json.dumps({"sw": sw, "step": "FINISH", "meaning": MEANINGS.get(sw, "status word %s" % sw)}))
        elif a.cmd == "verify":
            ok = ed25519_verify(bytes.fromhex(a.public_key), transaction_hash(a.passphrase, tx_of(a)), bytes.fromhex(a.signature))
            return 0 if ok else 1
        elif a.cmd == "attach":
            tx, signatures = split_envelope(a.envelope)
            public, signature = bytes.fromhex(a.public_key), bytes.fromhex(a.signature)
            if len(public) != 32 or len(signature) != 64:
                raise ValueError("a public key is 32 bytes and a signature 64")
            print(envelope(tx, signatures + [(public[-4:], signature)]))  # the hint is the key's last four bytes
        elif a.cmd == "server-signed":
            tx, signatures = split_envelope(a.envelope)
            source = tx[4:36]  # the transaction's source account: the server's signing key
            digest = transaction_hash(a.passphrase, tx)
            return 0 if any(hint == source[-4:] and ed25519_verify(source, digest, sig) for hint, sig in signatures) else 1
        elif a.cmd == "variant":
            if a.kind == "payment":
                if not (a.source and a.op_source and a.destination and a.stroops):
                    raise ValueError("payment needs --source, --op-source, --destination and --stroops")
                print(payment_tx(account_key(a.source), account_key(a.op_source), account_key(a.destination),
                                 a.stroops, a.challenge_shaped).hex())
            else:
                if not a.envelope:
                    raise ValueError("%s needs the envelope" % a.kind)
                tx = split_envelope(a.envelope)[0]
                if a.kind == "sequence":  # source account (4 + 32) and fee (4), then the 8-byte sequence number
                    print((tx[:40] + struct.pack(">q", 1) + tx[48:]).hex())
                else:
                    print((tx + b"\x00").hex())
        elif a.cmd == "self-test":
            self_test()
        else:
            ap.print_help(sys.stderr)
            return 1
    except (ValueError, RuntimeError, OSError, binascii.Error) as e:
        print("sep10-card: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
