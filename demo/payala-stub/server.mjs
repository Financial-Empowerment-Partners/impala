#!/usr/bin/env node
// demo/payala-stub — a stand-in for the Payala API, for the demo only.
//
// The demo's relays (scripts/payala/*) talk to a Payala backend. The real Payala API is proprietary and
// is NOT part of this repository or this demo: this file is a small clean-room stub of the subset the
// relays use, written from the wire contract documented in scripts/payala/payala-order.sh. No
// dependencies; Node >= 20; runs from docker.io/library/node:22-alpine with this directory bind-mounted
// (compose service payala-stub) or on the host (node server.mjs).
//
// Endpoints (JSON; no authentication — the stub counts and journals whether a request carried one):
//   GET  /                         health: {service, status, users, transfers, seeded_at, persistent}
//   GET  /users                    {"Data":[user…]}   user = {user_id, card_id, status, role, phone_nr,
//   GET  /users/:id                user                given_name, family_name, balance, currency}
//   POST /transfers/order          a remote transfer ("Order") the server signs itself. Body:
//                                  {device_id (base64, 12 bytes), sender_id, sender_name, recipient_id,
//                                   recipient_name, currency, amount (integer minor units), counter (0),
//                                   created_at (RFC 3339), hash (base64 sha256 of the preimage below),
//                                   sender_public_key (base64, 64 bytes P-256 X||Y)}
//                                  200 the transfer (counter -1 = server-signed; replayed:true when the
//                                  same hash was already applied), 200 null when the sender has no card,
//                                  400 malformed / self-transfer / hash_mismatch / currency_mismatch, 403 the
//                                  public key is not the sender card's signing key, 404 unknown user,
//                                  422 insufficient balance, 503 persistence failed (nothing applied).
//                                  Balances move in one synchronous step, once per hash, and only after
//                                  the state file was written.
//   GET  /transfers                {"Data":[transfer…]} filters: since (RFC 3339, inclusive on created_at),
//                                  overlap (seconds subtracted from since), device_id / hash (hex, base64 or
//                                  base64url), sender_id, recipient_id, limit. Ordered by created_at, then hash.
//   GET  /__stub/requests          the request journal (not the Payala API): {"Data":[{seq, at, method, path,
//                                  status, has_authorization, order?}]}  filters: since_seq, path, method.
//                                  In memory, newest JOURNAL_MAX entries; /__stub/* requests are not journaled.
//   GET  /__stub/state             {users, transfers, journal_seq, journal_size, journal_max, state_path,
//                                  seeded_at, counters:{requests_total, authorization_requests} (monotonic
//                                  since start, every request incl. /__stub/*), cards:[{id, user_id,
//                                  signing_public_key_hex}]}
//   GET  /__stub/healthz           {status:"ok"} — the compose healthcheck target (not journaled)
//
// Order preimage (256 bytes, big-endian; payala-order.sh builds the same bytes):
//   int64 created_at_ms | sender uuid (16) | recipient uuid (16) | currency NUL-padded to 4 | int32 amount |
//   device_id (12) | int32 counter | sender_public_key X||Y (64) | 64 zero bytes | 64 zero bytes
//
// Money: integer minor units (cents) only; every balance update is guarded by Number.isSafeInteger.
// State: in memory, optionally persisted to PAYALA_STUB_STATE as JSON (atomic rename) before a mutation is
// committed (a failed write answers 503 and leaves the ledger untouched) and loaded at boot; the seed file
// (PAYALA_STUB_SEED) only adds users that do not exist yet. The journal and the counters are not persisted.
// Notices go to stderr; the data is the HTTP response.

import http from 'node:http';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { pathToFileURL } from 'node:url';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const INT32_MAX = 2147483647;
export const JOURNAL_MAX = 2000;
export const BODY_MAX = 65536;
export const PREIMAGE_LEN = 256;

// ---------------------------------------------------------------- encoding helpers
export function uuidBytes(id) {
  return Buffer.from(id.replace(/-/g, ''), 'hex');
}

/** Strict base64 decode: the text must round-trip and decode to exactly `len` bytes; null otherwise. */
export function b64Bytes(text, len) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) return null;
  const buf = Buffer.from(text, 'base64');
  if (buf.length !== len || buf.toString('base64') !== text) return null;
  return buf;
}

/** Accept hex, base64 or base64url for a byte string of `len` bytes; returns lowercase hex or null.
 *  A '+' in a raw query string arrives as a space after URL decoding and is mapped back. */
export function bytesParam(text, len) {
  if (typeof text !== 'string') return null;
  if (new RegExp(`^[0-9a-fA-F]{${len * 2}}$`).test(text)) return text.toLowerCase();
  let b64 = text.replace(/ /g, '+').replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const buf = b64Bytes(b64, len);
  return buf ? buf.toString('hex') : null;
}

export function orderPreimage({ createdAtMs, senderId, recipientId, currency, amount, deviceId, counter, senderPublicKey }) {
  const b = Buffer.alloc(PREIMAGE_LEN); // zero-filled: the currency padding and the two 64-byte signature slots stay 0
  let o = 0;
  b.writeBigInt64BE(BigInt(createdAtMs), o); o += 8;
  uuidBytes(senderId).copy(b, o); o += 16;
  uuidBytes(recipientId).copy(b, o); o += 16;
  Buffer.from(currency, 'ascii').copy(b, o); o += 4;
  b.writeInt32BE(amount, o); o += 4;
  deviceId.copy(b, o); o += 12;
  b.writeInt32BE(counter, o); o += 4;
  senderPublicKey.copy(b, o); o += 64;
  if (o !== 128) throw new Error(`preimage layout: ${o}`);
  return b;
}

export function sha256(buf) {
  return createHash('sha256').update(buf).digest();
}

const isUuid = (v) => typeof v === 'string' && UUID_RE.test(v);

// ---------------------------------------------------------------- the ledger
export class Ledger {
  constructor({ statePath = null } = {}) {
    this.statePath = statePath;
    this.users = new Map();     // user_id (lower case) -> {user_id, card_id, status, role, phone_nr, given_name, family_name, balance, currency}
    this.cards = new Map();     // card_id (lower case) -> {id, user_id, status, signing_public_key_hex}
    this.transfers = [];        // in insertion order; listTransfers sorts
    this.byHash = new Map();    // hash_hex -> transfer
    this.journal = [];
    this.seq = 0;
    this.seededAt = null;
    this.counters = { requests_total: 0, authorization_requests: 0 }; // monotonic; never evicted like the journal
  }

  // ---- persistence
  load() {
    if (!this.statePath || !existsSync(this.statePath)) return false;
    const s = JSON.parse(readFileSync(this.statePath, 'utf8'));
    if (s.version !== 1) throw new Error(`state ${this.statePath}: unsupported version ${s.version}`);
    for (const u of s.users) {
      const id = String(u.user_id).toLowerCase();
      this.users.set(id, { ...u, user_id: id, card_id: u.card_id ? String(u.card_id).toLowerCase() : null });
    }
    for (const c of s.cards) {
      const id = String(c.id).toLowerCase();
      this.cards.set(id, { ...c, id, user_id: String(c.user_id).toLowerCase() });
    }
    for (const t of s.transfers) { this.transfers.push(t); this.byHash.set(t.hash_hex, t); }
    return true;
  }

  /** Write the ledger (atomic rename). Throws when the state cannot be written; callers decide what that means. */
  save() {
    if (!this.statePath) return;
    mkdirSync(dirname(this.statePath), { recursive: true });
    const tmp = `${this.statePath}.tmp`;
    writeFileSync(tmp, JSON.stringify({
      version: 1,
      users: [...this.users.values()],
      cards: [...this.cards.values()],
      transfers: this.transfers,
    }));
    renameSync(tmp, this.statePath);
  }

  /** Add the seed's users and cards that do not exist yet (balances and keys of existing ones are untouched). */
  seed(doc) {
    let added = 0;
    for (const u of doc.users || []) {
      if (!isUuid(u.id)) throw new Error(`seed: bad user id ${u.id}`);
      const id = u.id.toLowerCase();
      if (!Number.isSafeInteger(u.balance) || u.balance < 0) throw new Error(`seed: bad balance for ${id}`);
      if (typeof u.currency !== 'string' || !/^[A-Z]{1,4}$/.test(u.currency)) throw new Error(`seed: bad currency for ${id}`);
      let cardId = null;
      if (u.card) {
        if (!isUuid(u.card.id)) throw new Error(`seed: bad card id for ${id}`);
        if (typeof u.card.signing_public_key_hex !== 'string' || !/^[0-9a-fA-F]{128}$/.test(u.card.signing_public_key_hex)) throw new Error(`seed: card ${u.card.id}: signing_public_key_hex must be 128 hex chars`);
        cardId = u.card.id.toLowerCase();
        if (!this.cards.has(cardId)) {
          this.cards.set(cardId, { id: cardId, user_id: id, status: 'active', signing_public_key_hex: u.card.signing_public_key_hex.toLowerCase() });
        }
      }
      if (!this.users.has(id)) {
        this.users.set(id, {
          user_id: id, card_id: cardId, status: 'active', role: u.role || 'user', phone_nr: u.phone_nr || null,
          given_name: u.given_name || '', family_name: u.family_name || '', balance: u.balance, currency: u.currency,
        });
        added++;
      }
    }
    if (added) this.save(); // at boot a failed write is fatal (main exits), which is the right answer for a seed
    this.seededAt = new Date().toISOString();
    return added;
  }

  // ---- journal (the stub's own evidence; never part of the Payala API)
  record(entry) {
    this.seq += 1;
    const e = { seq: this.seq, at: new Date().toISOString(), ...entry };
    this.journal.push(e);
    if (this.journal.length > JOURNAL_MAX) this.journal.splice(0, this.journal.length - JOURNAL_MAX);
    return e;
  }

  listRequests({ since_seq, path, method } = {}) {
    const since = Number(since_seq || 0);
    return this.journal.filter((e) => e.seq > since && (!path || e.path.startsWith(path)) && (!method || e.method === method));
  }

  state() {
    return {
      users: this.users.size,
      transfers: this.transfers.length,
      journal_seq: this.seq,
      journal_size: this.journal.length,
      journal_max: JOURNAL_MAX,
      state_path: this.statePath,
      seeded_at: this.seededAt,
      counters: { ...this.counters },
      cards: [...this.cards.values()].map((c) => ({ id: c.id, user_id: c.user_id, signing_public_key_hex: c.signing_public_key_hex })),
    };
  }

  // ---- orders
  /** Returns {status, body, audit}; audit carries the request's ids for the journal even when it is refused. */
  order(body) {
    const audit = {};
    const bad = (status, error, detail) => ({ status, body: detail ? { error, detail } : { error }, audit });
    if (!body || typeof body !== 'object' || Array.isArray(body)) return bad(400, 'invalid_request', 'body must be a JSON object');
    const { device_id, sender_id, recipient_id, currency, amount, counter, created_at, hash, sender_public_key } = body;
    if (typeof sender_id === 'string') audit.sender_id = sender_id;
    if (typeof recipient_id === 'string') audit.recipient_id = recipient_id;
    if (Number.isSafeInteger(amount)) audit.amount = amount;
    const deviceId = b64Bytes(device_id, 12);
    if (deviceId) audit.device_id_hex = deviceId.toString('hex');
    const hashBytes = b64Bytes(hash, 32);
    if (hashBytes) audit.hash_hex = hashBytes.toString('hex');
    if (!isUuid(sender_id)) return bad(400, 'invalid_request', 'sender_id must be a uuid');
    if (!isUuid(recipient_id)) return bad(400, 'invalid_request', 'recipient_id must be a uuid');
    if (!deviceId) return bad(400, 'invalid_request', 'device_id must be base64 of 12 bytes');
    if (!hashBytes) return bad(400, 'invalid_request', 'hash must be base64 of 32 bytes');
    const pub = b64Bytes(sender_public_key, 64);
    if (!pub) return bad(400, 'invalid_request', 'sender_public_key must be base64 of 64 bytes (P-256 X||Y)');
    if (typeof currency !== 'string' || !/^[A-Z]{1,4}$/.test(currency)) return bad(400, 'invalid_request', 'currency must be 1-4 upper-case letters');
    if (!Number.isSafeInteger(amount) || amount < 1 || amount > INT32_MAX) return bad(400, 'invalid_request', 'amount must be an integer number of minor units in 1..2147483647');
    if (counter !== 0) return bad(400, 'invalid_request', 'counter must be 0 for a client order');
    const createdAtMs = typeof created_at === 'string' ? Date.parse(created_at) : NaN;
    if (!Number.isFinite(createdAtMs)) return bad(400, 'invalid_request', 'created_at must be an RFC 3339 timestamp');
    const sender = this.users.get(sender_id.toLowerCase());
    if (!sender) return bad(404, 'sender_not_found');
    const recipient = this.users.get(recipient_id.toLowerCase());
    if (!recipient) return bad(404, 'recipient_not_found');
    if (sender === recipient) return bad(400, 'invalid_request', 'sender_id and recipient_id must differ'); // a self-order must never mint
    if (!sender.card_id) return { status: 200, body: null, audit }; // the branch answers null for a cardless sender
    const card = this.cards.get(sender.card_id);
    if (!card || card.signing_public_key_hex !== pub.toString('hex')) return bad(403, 'sender_public_key_mismatch', 'not the signing key of the sender card');
    if (currency !== sender.currency || currency !== recipient.currency) return bad(400, 'currency_mismatch', `users are in ${sender.currency}/${recipient.currency}`);
    const expected = sha256(orderPreimage({ createdAtMs, senderId: sender_id, recipientId: recipient_id, currency, amount, deviceId, counter: 0, senderPublicKey: pub }));
    if (!expected.equals(hashBytes)) return bad(400, 'hash_mismatch', 'hash is not sha256(preimage)');
    const hashHex = hashBytes.toString('hex');
    const existing = this.byHash.get(hashHex);
    if (existing) return { status: 200, body: { ...existing, replayed: true }, audit };
    if (sender.balance < amount) return { status: 422, body: { error: 'insufficient_balance', balance: sender.balance, amount }, audit };
    const oldSender = sender.balance;
    const oldRecipient = recipient.balance;
    const newSender = oldSender - amount;
    const newRecipient = oldRecipient + amount;
    if (!Number.isSafeInteger(newSender) || !Number.isSafeInteger(newRecipient)) return bad(422, 'balance_out_of_range');
    const transfer = {
      id: randomUUID(),
      kind: 'Order',
      hash,
      hash_hex: hashHex,
      device_id,
      device_id_hex: deviceId.toString('hex'),
      sender_id: sender.user_id,
      sender_name: `${sender.given_name} ${sender.family_name}`.trim(),
      recipient_id: recipient.user_id,
      recipient_name: `${recipient.given_name} ${recipient.family_name}`.trim(),
      currency,
      amount,
      counter: -1, // negative: signed by the server, not by a card
      created_at: new Date(createdAtMs).toISOString(),
      received_at: new Date().toISOString(),
      sender_public_key,
    };
    // The whole mutation happens in this synchronous turn (no interleaving). It is committed only if the
    // state file was written: on a failed write everything is rolled back and the caller gets a 503.
    sender.balance = newSender;
    recipient.balance = newRecipient;
    this.transfers.push(transfer);
    this.byHash.set(hashHex, transfer);
    try {
      this.save();
    } catch (e) {
      sender.balance = oldSender;
      recipient.balance = oldRecipient;
      this.transfers.pop();
      this.byHash.delete(hashHex);
      return { status: 503, body: { error: 'persistence_failed', detail: String(e && e.message) }, audit };
    }
    return { status: 200, body: transfer, audit };
  }

  listTransfers(q = {}) {
    let sinceMs = null;
    if (q.since) {
      sinceMs = Date.parse(q.since);
      if (!Number.isFinite(sinceMs)) return { error: 'since must be an RFC 3339 timestamp' };
      const overlap = q.overlap === undefined ? 0 : Number(q.overlap);
      if (!Number.isSafeInteger(overlap) || overlap < 0) return { error: 'overlap must be a non-negative integer number of seconds' };
      sinceMs -= overlap * 1000;
    }
    let deviceHex = null;
    if (q.device_id !== undefined) { deviceHex = bytesParam(q.device_id, 12); if (!deviceHex) return { error: 'device_id must be 12 bytes as hex or base64' }; }
    let hashHex = null;
    if (q.hash !== undefined) { hashHex = bytesParam(q.hash, 32); if (!hashHex) return { error: 'hash must be 32 bytes as hex or base64' }; }
    const limit = q.limit === undefined ? 10000 : Number(q.limit);
    if (!Number.isSafeInteger(limit) || limit < 1) return { error: 'limit must be a positive integer' };
    const senderId = typeof q.sender_id === 'string' ? q.sender_id.toLowerCase() : null;
    const recipientId = typeof q.recipient_id === 'string' ? q.recipient_id.toLowerCase() : null;
    const rows = this.transfers.filter((t) =>
      (sinceMs === null || Date.parse(t.created_at) >= sinceMs)
      && (deviceHex === null || t.device_id_hex === deviceHex)
      && (hashHex === null || t.hash_hex === hashHex)
      && (!senderId || t.sender_id === senderId)
      && (!recipientId || t.recipient_id === recipientId));
    rows.sort((a, b) => (Date.parse(a.created_at) - Date.parse(b.created_at)) || (a.hash_hex < b.hash_hex ? -1 : a.hash_hex > b.hash_hex ? 1 : 0));
    return { rows: rows.slice(0, limit) };
  }
}

// ---------------------------------------------------------------- HTTP
/** Resolve {text} or, once more than `max` bytes arrived, {tooLarge:true} with the request paused. */
function readBody(req, max) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;
    req.on('data', (c) => {
      if (done) return;
      size += c.length;
      if (size > max) { done = true; req.pause(); resolve({ tooLarge: true }); return; }
      chunks.push(c);
    });
    req.on('end', () => { if (!done) { done = true; resolve({ text: Buffer.concat(chunks).toString('utf8') }); } });
    req.on('error', (e) => { if (!done) { done = true; reject(e); } });
  });
}

export function createApp(ledger, { log = () => {} } = {}) {
  // Nothing in here may throw out of the async listener: an unhandled rejection would stop the process.
  return async (req, res) => {
    const started = Date.now();
    const entry = { method: req.method, path: typeof req.url === 'string' ? req.url : '/', has_authorization: req.headers.authorization !== undefined };
    ledger.counters.requests_total += 1;
    if (entry.has_authorization) ledger.counters.authorization_requests += 1;
    let status = 500;
    let body = { error: 'internal' };
    let closeAfter = false;
    let path = entry.path;
    try {
      let url = null;
      try { url = new URL(req.url, 'http://payala-stub'); } catch { url = null; }
      if (!url) {
        status = 400; body = { error: 'invalid_request', detail: 'malformed request target' };
      } else {
        path = url.pathname;
        entry.path = path;
        const q = Object.fromEntries(url.searchParams);
        status = 404; body = { error: 'not_found' };
        if (req.method === 'GET' && path === '/') {
          status = 200;
          body = { service: 'payala-stub', status: 'ok', users: ledger.users.size, transfers: ledger.transfers.length, seeded_at: ledger.seededAt, persistent: Boolean(ledger.statePath) };
        } else if (req.method === 'GET' && path === '/users') {
          status = 200;
          body = { Data: [...ledger.users.values()] };
        } else if (req.method === 'GET' && /^\/users\/[^/]+$/.test(path)) {
          let id = null;
          try { id = decodeURIComponent(path.slice('/users/'.length)).toLowerCase(); } catch { id = null; }
          if (id === null) { status = 400; body = { error: 'invalid_request', detail: 'malformed user id' }; } else {
            const u = ledger.users.get(id);
            if (u) { status = 200; body = u; } else { status = 404; body = { error: 'user_not_found' }; }
          }
        } else if (path === '/transfers/order') {
          if (req.method !== 'POST') { status = 405; body = { error: 'method_not_allowed' }; } else {
            const b = await readBody(req, BODY_MAX);
            if (b.tooLarge) {
              status = 413; body = { error: 'payload_too_large', max_bytes: BODY_MAX }; closeAfter = true;
            } else {
              let parsed;
              try { parsed = JSON.parse(b.text); } catch { parsed = undefined; }
              if (parsed === undefined) { status = 400; body = { error: 'invalid_json' }; } else {
                const r = ledger.order(parsed);
                status = r.status; body = r.body;
                if (Object.keys(r.audit).length) entry.order = r.audit;
              }
            }
          }
        } else if (req.method === 'GET' && path === '/transfers') {
          const r = ledger.listTransfers(q);
          if (r.error) { status = 400; body = { error: 'invalid_request', detail: r.error }; } else { status = 200; body = { Data: r.rows }; }
        } else if (req.method === 'GET' && path === '/__stub/requests') {
          status = 200;
          body = { Data: ledger.listRequests(q) };
        } else if (req.method === 'GET' && path === '/__stub/state') {
          status = 200;
          body = ledger.state();
        } else if (req.method === 'GET' && path === '/__stub/healthz') {
          status = 200;
          body = { status: 'ok' };
        }
      }
    } catch (e) {
      status = 500; body = { error: 'internal', detail: String(e && e.message) };
    }
    if (!path.startsWith('/__stub/')) ledger.record({ ...entry, status });
    const text = JSON.stringify(body);
    const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) };
    if (closeAfter) headers.Connection = 'close';
    try {
      res.writeHead(status, headers);
      if (closeAfter) res.end(text, () => req.destroy()); else res.end(text);
    } catch (e) {
      log(`response failed: ${e && e.message}`);
    }
    log(`${req.method} ${path} ${status} ${Date.now() - started}ms`);
  };
}

export function startServer(ledger, { port = 4000, host = '0.0.0.0', log } = {}) {
  const server = http.createServer(createApp(ledger, { log }));
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve(server));
  });
}

// ---------------------------------------------------------------- main
async function main() {
  const port = Number(process.env.PAYALA_STUB_PORT || 4000);
  const ledger = new Ledger({ statePath: process.env.PAYALA_STUB_STATE || null });
  const loaded = ledger.load();
  const seedPath = process.env.PAYALA_STUB_SEED;
  if (seedPath) {
    const added = ledger.seed(JSON.parse(readFileSync(seedPath, 'utf8')));
    console.error(`payala-stub: seed ${seedPath}: ${added} user(s) added, ${ledger.users.size} total, ${ledger.transfers.length} transfer(s)${loaded ? ` (state loaded from ${ledger.statePath})` : ''}`);
  }
  // belt and braces: the listener is catch-all, but a rejection must never take the stub (PID 1) down
  process.on('unhandledRejection', (e) => console.error(`payala-stub: unhandled rejection: ${(e && e.stack) || e}`));
  const server = await startServer(ledger, { port, log: (line) => console.error(`payala-stub: ${line}`) });
  console.error(`payala-stub: listening on :${port}${ledger.statePath ? `, state ${ledger.statePath}` : ', in-memory only'}`);
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { server.close(); process.exit(0); });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => { console.error(`payala-stub: ${e.message}`); process.exit(1); });
}
