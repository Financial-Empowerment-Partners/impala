#!/usr/bin/env python3
"""Recording proxy for the impala-card simulator's TCP framing (2-byte big-endian length + bytes, both ways).
Usage: proxy.py LISTEN_PORT TARGET_PORT OUT_FILE   (serves connections until killed; appends to OUT_FILE)"""
import socket, struct, sys

def read_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            return None
        b += c
    return b

def frame(s):
    h = read_exact(s, 2)
    if h is None:
        return None
    return read_exact(s, struct.unpack(">H", h)[0])

listen, target, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", listen)); srv.listen(1)
while True:
    c, _ = srv.accept()
    t = socket.create_connection(("127.0.0.1", target), timeout=30)
    with open(out, "a") as f:
        f.write("# connection\n")
        while True:
            cmd = frame(c)
            if cmd is None:
                break
            t.sendall(struct.pack(">H", len(cmd)) + cmd)
            resp = frame(t)
            if resp is None:
                break
            f.write("> %s\n< %s\n" % (cmd.hex(), resp.hex())); f.flush()
            c.sendall(struct.pack(">H", len(resp)) + resp)
    c.close(); t.close()
