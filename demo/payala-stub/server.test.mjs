// node --test demo/payala-stub/server.test.mjs   (Node >= 20, no dependencies)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Ledger, createApp, orderPreimage, sha256, b64Bytes, bytesParam, PREIMAGE_LEN } from './server.mjs';

const MINT = '10000000-0000-4000-8000-000000000001';
const AGENT = '10000000-0000-4000-8000-000000000003';
const BENEF = '10000000-0000-4000-8000-000000000004';
const NOCARD = '10000000-0000-4000-8000-000000000009';

/** A P-256 key pair; the raw 64-byte X||Y is what a Payala card stores as its signing key. */
function keyPair() {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const raw = Buffer.concat([Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  assert.equal(raw.length, 64);
  return { raw, hex: raw.toString('hex'), b64: raw.toString('base64') };
}

const KEYS = { [MINT]: keyPair(), [AGENT]: keyPair(), [BENEF]: keyPair() };

function seedDoc() {
  return {
    users: [
      { id: MINT, role: 'admin', given_name: 'Payala', family_name: 'Mint', balance: 1000000000, currency: 'USD', card: { id: '20000000-0000-4000-8000-000000000001', signing_public_key_hex: KEYS[MINT].hex } },
      { id: AGENT, role: 'agent', given_name: 'Ada', family_name: 'Agent', balance: 0, currency: 'USD', card: { id: '20000000-0000-4000-8000-000000000003', signing_public_key_hex: KEYS[AGENT].hex } },
      { id: BENEF, role: 'user', given_name: 'Ben', family_name: 'Beneficiary', balance: 0, currency: 'USD', card: { id: '20000000-0000-4000-8000-000000000004', signing_public_key_hex: KEYS[BENEF].hex } },
      { id: NOCARD, role: 'user', given_name: 'No', family_name: 'Card', balance: 500, currency: 'USD' },
    ],
  };
}

/** Build an order body exactly the way scripts/payala/payala-order.sh does. */
function orderBody({ sender, recipient, amount, deviceHex, createdAt = '2026-10-09T12:00:00Z', pub = KEYS[sender], currency = 'USD', counter = 0 }) {
  const deviceId = Buffer.from(deviceHex, 'hex');
  const pre = orderPreimage({ createdAtMs: Date.parse(createdAt), senderId: sender, recipientId: recipient, currency, amount, deviceId, counter, senderPublicKey: pub.raw });
  return {
    device_id: deviceId.toString('base64'), sender_id: sender, sender_name: '', recipient_id: recipient, recipient_name: '',
    currency, amount, counter, created_at: createdAt, hash: sha256(pre).toString('base64'), sender_public_key: pub.b64,
  };
}

function fresh() {
  const l = new Ledger();
  l.seed(seedDoc());
  return l;
}

test('preimage layout is 256 bytes with the documented field order', () => {
  const pre = orderPreimage({ createdAtMs: 1760000000000, senderId: AGENT, recipientId: BENEF, currency: 'USD', amount: 1234, deviceId: Buffer.alloc(12, 0xab), counter: 0, senderPublicKey: Buffer.alloc(64, 0xcd) });
  assert.equal(pre.length, PREIMAGE_LEN);
  assert.equal(pre.readBigInt64BE(0), 1760000000000n);
  assert.equal(pre.subarray(8, 24).toString('hex'), AGENT.replace(/-/g, ''));
  assert.equal(pre.subarray(24, 40).toString('hex'), BENEF.replace(/-/g, ''));
  assert.equal(pre.subarray(40, 44).toString('hex'), '55534400'); // "USD\0"
  assert.equal(pre.readInt32BE(44), 1234);
  assert.equal(pre.subarray(48, 60).toString('hex'), 'ab'.repeat(12));
  assert.equal(pre.readInt32BE(60), 0);
  assert.equal(pre.subarray(64, 128).toString('hex'), 'cd'.repeat(64));
  assert.equal(pre.subarray(128).toString('hex'), '00'.repeat(128));
});

test('strict base64 and hex-or-base64 parameters', () => {
  assert.equal(b64Bytes(Buffer.alloc(12, 1).toString('base64'), 12).length, 12);
  assert.equal(b64Bytes('not base64!', 12), null);
  assert.equal(b64Bytes(Buffer.alloc(11, 1).toString('base64'), 12), null);
  assert.equal(bytesParam('AB'.repeat(12), 12), 'ab'.repeat(12));
  assert.equal(bytesParam(Buffer.from('ab'.repeat(12), 'hex').toString('base64'), 12), 'ab'.repeat(12));
  assert.equal(bytesParam('zz', 12), null);
});

test('seeding is idempotent and never resets balances', () => {
  const l = fresh();
  assert.equal(l.users.size, 4);
  const r = l.order(orderBody({ sender: MINT, recipient: AGENT, amount: 50000, deviceHex: '01'.repeat(12) }));
  assert.equal(r.status, 200);
  assert.equal(l.seed(seedDoc()), 0);
  assert.equal(l.users.get(AGENT).balance, 50000);
  assert.equal(l.users.get(MINT).balance, 1000000000 - 50000);
});

test('a valid order moves the balances once; the same hash replays without moving them again', () => {
  const l = fresh();
  l.order(orderBody({ sender: MINT, recipient: AGENT, amount: 50000, deviceHex: '01'.repeat(12) }));
  const body = orderBody({ sender: AGENT, recipient: BENEF, amount: 1234, deviceHex: 'aa'.repeat(12) });
  const r = l.order(body);
  assert.equal(r.status, 200);
  assert.equal(r.body.kind, 'Order');
  assert.equal(r.body.counter, -1);
  assert.equal(r.body.hash, body.hash);
  assert.equal(r.body.hash_hex, Buffer.from(body.hash, 'base64').toString('hex'));
  assert.equal(r.body.device_id_hex, 'aa'.repeat(12));
  assert.equal(r.body.sender_name, 'Ada Agent');
  assert.equal(r.body.recipient_name, 'Ben Beneficiary');
  assert.equal(r.body.created_at, '2026-10-09T12:00:00.000Z');
  assert.equal(l.users.get(AGENT).balance, 50000 - 1234);
  assert.equal(l.users.get(BENEF).balance, 1234);
  const again = l.order(body);
  assert.equal(again.status, 200);
  assert.equal(again.body.replayed, true);
  assert.equal(again.body.hash_hex, r.body.hash_hex);
  assert.equal(l.users.get(AGENT).balance, 50000 - 1234);
  assert.equal(l.users.get(BENEF).balance, 1234);
  assert.equal(l.transfers.length, 2);
  assert.deepEqual(r.audit, { sender_id: AGENT, recipient_id: BENEF, amount: 1234, device_id_hex: 'aa'.repeat(12), hash_hex: r.body.hash_hex });
});

test('refusals: wrong key 403, wrong hash 400, insufficient 422, cardless sender null, unknown users 404, bad fields 400', () => {
  const l = fresh();
  l.order(orderBody({ sender: MINT, recipient: AGENT, amount: 100, deviceHex: '01'.repeat(12) }));
  const other = keyPair();
  assert.equal(l.order(orderBody({ sender: AGENT, recipient: BENEF, amount: 10, deviceHex: '02'.repeat(12), pub: other })).status, 403);
  const tampered = orderBody({ sender: AGENT, recipient: BENEF, amount: 10, deviceHex: '03'.repeat(12) });
  tampered.amount = 11; // the hash no longer covers the body
  const t = l.order(tampered);
  assert.equal(t.status, 400); assert.equal(t.body.error, 'hash_mismatch');
  const poor = l.order(orderBody({ sender: AGENT, recipient: BENEF, amount: 101, deviceHex: '04'.repeat(12) }));
  assert.equal(poor.status, 422); assert.equal(poor.body.error, 'insufficient_balance');
  const cardless = l.order(orderBody({ sender: NOCARD, recipient: BENEF, amount: 1, deviceHex: '05'.repeat(12), pub: other }));
  assert.equal(cardless.status, 200); assert.equal(cardless.body, null);
  assert.equal(l.order(orderBody({ sender: AGENT, recipient: '10000000-0000-4000-8000-00000000ffff', amount: 1, deviceHex: '06'.repeat(12) })).status, 404);
  assert.equal(l.order(orderBody({ sender: '10000000-0000-4000-8000-00000000fffe', recipient: BENEF, amount: 1, deviceHex: '06'.repeat(12), pub: other })).status, 404);
  assert.equal(l.order(orderBody({ sender: AGENT, recipient: BENEF, amount: 0, deviceHex: '07'.repeat(12) })).status, 400);
  assert.equal(l.order({ ...orderBody({ sender: AGENT, recipient: BENEF, amount: 1, deviceHex: '07'.repeat(12) }), amount: 2147483648 }).status, 400);
  assert.equal(l.order(orderBody({ sender: AGENT, recipient: BENEF, amount: 1, deviceHex: '08'.repeat(12), counter: 1 })).status, 400);
  assert.equal(l.order(orderBody({ sender: AGENT, recipient: BENEF, amount: 1, deviceHex: '09'.repeat(12), currency: 'EUR' })).body.error, 'currency_mismatch');
  assert.equal(l.order({ ...orderBody({ sender: AGENT, recipient: BENEF, amount: 1, deviceHex: '0a'.repeat(12) }), device_id: 'AAAA' }).status, 400);
  assert.equal(l.order('nope').status, 400);
  // nothing above moved money
  assert.equal(l.users.get(AGENT).balance, 100);
  assert.equal(l.users.get(BENEF).balance, 0);
  assert.equal(l.transfers.length, 1);
});

test('listTransfers: since/overlap, device_id (hex or base64), hash, ordering, limit', () => {
  const l = fresh();
  l.order(orderBody({ sender: MINT, recipient: AGENT, amount: 1000, deviceHex: '01'.repeat(12), createdAt: '2026-10-09T10:00:00Z' }));
  l.order(orderBody({ sender: AGENT, recipient: BENEF, amount: 10, deviceHex: 'bb'.repeat(12), createdAt: '2026-10-09T12:00:30Z' }));
  l.order(orderBody({ sender: AGENT, recipient: BENEF, amount: 20, deviceHex: 'cc'.repeat(12), createdAt: '2026-10-09T12:00:00Z' }));
  const all = l.listTransfers({}).rows;
  assert.deepEqual(all.map((t) => t.amount), [1000, 20, 10]);
  assert.deepEqual(l.listTransfers({ since: '2026-10-09T12:00:30Z' }).rows.map((t) => t.amount), [10]);
  assert.deepEqual(l.listTransfers({ since: '2026-10-09T12:00:30Z', overlap: 60 }).rows.map((t) => t.amount), [20, 10]);
  assert.deepEqual(l.listTransfers({ device_id: 'cc'.repeat(12) }).rows.map((t) => t.amount), [20]);
  assert.deepEqual(l.listTransfers({ device_id: Buffer.from('cc'.repeat(12), 'hex').toString('base64') }).rows.map((t) => t.amount), [20]);
  assert.deepEqual(l.listTransfers({ hash: all[2].hash_hex }).rows.map((t) => t.amount), [10]);
  assert.deepEqual(l.listTransfers({ hash: all[2].hash }).rows.map((t) => t.amount), [10]);
  assert.deepEqual(l.listTransfers({ sender_id: AGENT, limit: 1 }).rows.map((t) => t.amount), [20]);
  assert.ok(l.listTransfers({ since: 'yesterday' }).error);
  assert.ok(l.listTransfers({ device_id: 'zz' }).error);
  assert.ok(l.listTransfers({ limit: 0 }).error);
});

test('persistence: state survives a restart and the seed does not reset it', () => {
  const dir = mkdtempSync(join(tmpdir(), 'payala-stub-'));
  try {
    const statePath = join(dir, 'nested', 'state.json');
    const l = new Ledger({ statePath });
    assert.equal(l.load(), false);
    l.seed(seedDoc());
    l.order(orderBody({ sender: MINT, recipient: AGENT, amount: 777, deviceHex: '0d'.repeat(12) }));
    const l2 = new Ledger({ statePath });
    assert.equal(l2.load(), true);
    assert.equal(l2.seed(seedDoc()), 0);
    assert.equal(l2.users.get(AGENT).balance, 777);
    assert.equal(l2.transfers.length, 1);
    assert.equal(l2.byHash.size, 1);
    // the replay guard survived too
    const again = l2.order(orderBody({ sender: MINT, recipient: AGENT, amount: 777, deviceHex: '0d'.repeat(12) }));
    assert.equal(again.body.replayed, true);
    assert.equal(l2.users.get(AGENT).balance, 777);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** Spin the HTTP app up on an ephemeral port and return a tiny client. */
async function withServer(fn) {
  const l = fresh();
  const server = http.createServer(createApp(l));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = (method, path, body, headers = {}) => new Promise((resolve, reject) => {
    const req = http.request(`${base}${path}`, { method, headers: { 'content-type': 'application/json', ...headers } }, (res) => {
      let text = '';
      res.on('data', (c) => { text += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(text) }));
    });
    req.on('error', reject);
    if (body !== undefined) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
  try { await fn(call, l, server.address().port); } finally { await new Promise((r) => server.close(r)); }
}

/** One raw HTTP exchange over a TCP socket; resolves with everything received once the headers are complete. */
function rawRequest(port, text) {
  return new Promise((resolve, reject) => {
    let data = '';
    const s = net.connect(port, '127.0.0.1', () => s.write(text));
    s.on('data', (c) => { data += c; if (data.includes('\r\n\r\n')) s.destroy(); });
    s.on('close', () => resolve(data));
    s.on('error', reject);
  });
}

test('HTTP: health, users, orders, transfers, journal', async () => {
  await withServer(async (call, l) => {
    const h = await call('GET', '/');
    assert.equal(h.status, 200);
    assert.equal(h.body.service, 'payala-stub');
    assert.equal(h.body.users, 4);
    assert.equal(h.body.persistent, false);
    const users = await call('GET', '/users');
    assert.equal(users.body.Data.length, 4);
    assert.equal(users.body.Data.filter((u) => u.card_id !== null).length, 3);
    assert.equal((await call('GET', `/users/${AGENT}`)).body.balance, 0);
    assert.equal((await call('GET', `/users/${AGENT.toUpperCase()}`)).status, 200);
    assert.equal((await call('GET', '/users/10000000-0000-4000-8000-00000000ffff')).status, 404);
    const fund = await call('POST', '/transfers/order', orderBody({ sender: MINT, recipient: AGENT, amount: 500, deviceHex: '11'.repeat(12) }));
    assert.equal(fund.status, 200);
    assert.equal(fund.body.counter, -1);
    assert.equal((await call('GET', `/users/${AGENT}`)).body.balance, 500);
    assert.equal((await call('POST', '/transfers/order', '{not json')).status, 400);
    assert.equal((await call('GET', '/transfers/order')).status, 405);
    assert.equal((await call('POST', '/transfers/order', orderBody({ sender: NOCARD, recipient: AGENT, amount: 1, deviceHex: '12'.repeat(12), pub: KEYS[MINT] }))).body, null);
    const list = await call('GET', `/transfers?device_id=${'11'.repeat(12)}`);
    assert.equal(list.body.Data.length, 1);
    assert.equal(list.body.Data[0].hash_hex, fund.body.hash_hex);
    assert.equal((await call('GET', '/transfers?since=nope')).status, 400);
    assert.equal((await call('GET', '/nowhere')).status, 404);
    await call('GET', '/users', undefined, { authorization: 'Bearer should-never-happen' });
    const journal = (await call('GET', '/__stub/requests')).body.Data;
    assert.ok(journal.every((e) => !e.path.startsWith('/__stub/')));
    const orders = journal.filter((e) => e.path === '/transfers/order' && e.method === 'POST');
    assert.equal(orders.length, 3);
    assert.equal(orders[0].status, 200);
    assert.equal(orders[0].order.device_id_hex, '11'.repeat(12));
    assert.equal(orders[0].order.hash_hex, fund.body.hash_hex);
    assert.equal(orders[1].status, 400);
    assert.equal(orders[1].order, undefined);
    assert.equal(journal.filter((e) => e.has_authorization).length, 1);
    const since = (await call('GET', `/__stub/requests?since_seq=${orders[2].seq}&path=/transfers`)).body.Data;
    assert.deepEqual(since.map((e) => e.path), ['/transfers', '/transfers']);
    const state = (await call('GET', '/__stub/state')).body;
    assert.equal(state.transfers, 1);
    assert.equal(state.journal_seq, l.seq);
    assert.equal(state.counters.authorization_requests, 1);
    assert.equal(state.counters.requests_total, l.counters.requests_total);
    assert.equal(state.cards.length, 3);
    assert.equal(state.cards.find((c) => c.user_id === AGENT).signing_public_key_hex, KEYS[AGENT].hex);
  });
});

test('a self-transfer is refused and nothing is minted', () => {
  const l = fresh();
  l.order(orderBody({ sender: MINT, recipient: AGENT, amount: 100, deviceHex: '01'.repeat(12) }));
  const before = [...l.users.values()].reduce((s, u) => s + u.balance, 0);
  const r = l.order(orderBody({ sender: AGENT, recipient: AGENT, amount: 50, deviceHex: '02'.repeat(12) }));
  assert.equal(r.status, 400);
  const mixed = l.order(orderBody({ sender: AGENT, recipient: AGENT.toUpperCase(), amount: 50, deviceHex: '03'.repeat(12) }));
  assert.equal(mixed.status, 400);
  assert.equal(l.users.get(AGENT).balance, 100);
  assert.equal([...l.users.values()].reduce((s, u) => s + u.balance, 0), before);
  assert.equal(l.transfers.length, 1);
});

test('a failed state write answers 503 and rolls the ledger back', () => {
  const dir = mkdtempSync(join(tmpdir(), 'payala-stub-'));
  try {
    writeFileSync(join(dir, 'blocker'), 'not a directory');
    const l = fresh();
    l.order(orderBody({ sender: MINT, recipient: AGENT, amount: 100, deviceHex: '01'.repeat(12) }));
    l.statePath = join(dir, 'blocker', 'state.json'); // mkdirSync fails with ENOTDIR
    const r = l.order(orderBody({ sender: AGENT, recipient: BENEF, amount: 10, deviceHex: '04'.repeat(12) }));
    assert.equal(r.status, 503);
    assert.equal(r.body.error, 'persistence_failed');
    assert.equal(l.users.get(AGENT).balance, 100);
    assert.equal(l.users.get(BENEF).balance, 0);
    assert.equal(l.transfers.length, 1);
    assert.equal(l.byHash.size, 1);
    assert.equal(r.audit.device_id_hex, '04'.repeat(12)); // the journal still gets the audit of the refused order
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('seed ids are normalised to lower case, so every lookup finds them', () => {
  const l = new Ledger();
  const d = seedDoc();
  d.users[1].id = AGENT.toUpperCase();
  d.users[1].card.id = d.users[1].card.id.toUpperCase();
  l.seed(d);
  assert.ok(l.users.get(AGENT));
  assert.equal(l.users.get(AGENT).card_id, '20000000-0000-4000-8000-000000000003');
  assert.ok(l.cards.get('20000000-0000-4000-8000-000000000003'));
  assert.equal(l.order(orderBody({ sender: MINT, recipient: AGENT.toUpperCase(), amount: 5, deviceHex: '05'.repeat(12) })).status, 200);
  assert.equal(l.users.get(AGENT).balance, 5);
});

test('bytesParam accepts base64 whose + arrived as a space, and base64url', () => {
  const hex = 'fbefbe'.repeat(4);
  const b64 = Buffer.from(hex, 'hex').toString('base64');
  assert.equal(b64, '++++++++++++++++');
  assert.equal(bytesParam(b64, 12), hex);
  assert.equal(bytesParam(b64.replace(/\+/g, ' '), 12), hex);
  assert.equal(bytesParam(Buffer.from(hex, 'hex').toString('base64url'), 12), hex);
});

test('HTTP robustness: malformed target 400 (server survives), real 413, wrong-typed ids 400, base64 + in a query, healthz not journaled', async () => {
  await withServer(async (call, l, port) => {
    const bad = await rawRequest(port, 'GET http://[::1 HTTP/1.1\r\nHost: x\r\n\r\n');
    assert.match(bad, /^HTTP\/1\.1 400 /);
    assert.equal((await call('GET', '/')).status, 200); // still alive
    const big = await rawRequest(port, `POST /transfers/order HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 70000\r\n\r\n${'x'.repeat(70000)}`);
    assert.match(big, /^HTTP\/1\.1 413 /);
    assert.equal((await call('GET', '/')).status, 200);
    const typed = await call('POST', '/transfers/order', { ...orderBody({ sender: AGENT, recipient: BENEF, amount: 1, deviceHex: '06'.repeat(12) }), sender_id: [AGENT] });
    assert.equal(typed.status, 400);
    assert.equal((await call('GET', '/users/%E0%A4%A')).status, 400);
    l.order(orderBody({ sender: MINT, recipient: AGENT, amount: 7, deviceHex: 'fbefbe'.repeat(4) }));
    assert.equal((await call('GET', '/transfers?device_id=++++++++++++++++')).body.Data.length, 1);
    assert.equal((await call('GET', '/transfers?device_id=%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B%2B')).body.Data.length, 1);
    assert.equal((await call('GET', '/__stub/healthz')).body.status, 'ok');
    const journal = (await call('GET', '/__stub/requests')).body.Data;
    assert.ok(journal.every((e) => !e.path.startsWith('/__stub/')));
    assert.equal(journal.filter((e) => e.status === 413).length, 1);
    assert.equal(journal.filter((e) => e.status === 400 && e.path === 'http://[::1').length, 1);
    const state = (await call('GET', '/__stub/state')).body;
    assert.ok(state.counters.requests_total > journal.length); // /__stub/* requests count but are not journaled
  });
});
