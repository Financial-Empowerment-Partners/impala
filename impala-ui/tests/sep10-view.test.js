import { describe, it, expect, beforeAll } from 'vitest';
import { loadScript } from './helpers/load-script.js';

// sep10-view.js decides everything the SEP-10 signing-key panel shows and
// sends: badges, notices, which key offers which action, the confirmation
// phrases and the request bodies (docs/sep10-card-keys.md section 6.1).
let V;
beforeAll(() => {
    V = loadScript('sep10-view.js', 'Sep10View');
});

const ADDR_1 = 'GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ';
const ADDR_2 = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
const FP_1 = 'a1'.repeat(32);
const FP_2 = 'b2'.repeat(32);
const NOW = Date.parse('2026-11-12T12:00:00Z');
const MANAGER = { canManage: true };
const VIEWER = { canManage: false };

function key(overrides) {
    return Object.assign({
        version: 1,
        state: 'active',
        public_address: ADDR_1,
        fingerprint: FP_1,
        generated_by: 'custodian-1',
        generated_at: '2026-11-01T10:00:00Z',
        activate_at: '2026-11-01T10:05:00Z',
        superseded_at: null,
        revoked_at: null
    }, overrides || {});
}

function payload(overrides) {
    return Object.assign({
        enabled: true,
        home_domain: 'api-testnet.example.org',
        web_auth_endpoint: 'https://api-testnet.example.org/auth/sep10',
        network: 'testnet',
        network_passphrase: 'Test SDF Network ; September 2015',
        challenge_ttl_secs: 300,
        registered_card_keys: 3,
        keys: []
    }, overrides || {});
}

function status(overrides) {
    return V.normalizeStatus(payload(overrides));
}

const PENDING = () => key({ version: 2, state: 'pending', public_address: ADDR_2, fingerprint: FP_2, activate_at: null });
const ACTIVE = () => key();

describe('normalizeStatus', () => {
    it('reads the documented payload', () => {
        const s = status({ keys: [PENDING(), ACTIVE()] });
        expect(s.enabled).toBe(true);
        expect(s.network).toBe('testnet');
        expect(s.networkValid).toBe(true);
        expect(s.homeDomain).toBe('api-testnet.example.org');
        expect(s.webAuthEndpoint).toBe('https://api-testnet.example.org/auth/sep10');
        expect(s.networkPassphrase).toBe('Test SDF Network ; September 2015');
        expect(s.challengeTtlSecs).toBe(300);
        expect(s.registeredCardKeys).toBe(3);
        expect(s.keys).toHaveLength(2);
        expect(s.keys[0]).toMatchObject({
            version: 2, state: 'pending', knownState: 'pending',
            publicAddress: ADDR_2, fingerprint: FP_2, activateAt: null
        });
        expect(s.keysMalformed).toBe(false);
    });

    it('keeps the server order of keys (newest first per the contract)', () => {
        const s = status({ keys: [key({ version: 3, state: 'pending', activate_at: null }), key({ version: 1 })] });
        expect(s.keys.map((k) => k.version)).toEqual([3, 1]);
    });

    it('tolerates a missing or non-object payload', () => {
        for (const p of [undefined, null, 'oops', 42, []]) {
            const s = V.normalizeStatus(p);
            expect(s.enabled).toBeNull();
            expect(s.network).toBeNull();
            expect(s.networkValid).toBe(false);
            expect(s.keys).toEqual([]);
            expect(s.keysMalformed).toBe(true);
        }
    });

    it('turns missing and wrongly typed fields into null', () => {
        const s = V.normalizeStatus({
            enabled: 'yes', home_domain: 7, web_auth_endpoint: '', network: null,
            challenge_ttl_secs: -5, registered_card_keys: 1.5, keys: [{ version: '2', state: 9 }, 'junk']
        });
        expect(s.enabled).toBeNull();
        expect(s.homeDomain).toBeNull();
        expect(s.webAuthEndpoint).toBeNull();
        expect(s.network).toBeNull();
        expect(s.challengeTtlSecs).toBeNull();
        expect(s.registeredCardKeys).toBeNull();
        expect(s.keys).toHaveLength(2);
        expect(s.keys[0].version).toBeNull();
        expect(s.keys[0].state).toBeNull();
        expect(s.keys[0].knownState).toBeNull();
        expect(s.keys[1].version).toBeNull();
    });

    it('accepts null home_domain and web_auth_endpoint (endpoint not configured)', () => {
        const s = status({ home_domain: null, web_auth_endpoint: null });
        expect(s.homeDomain).toBeNull();
        expect(s.webAuthEndpoint).toBeNull();
    });

    it('rejects a network word that could not be a phrase token', () => {
        for (const n of ['Testnet', 'test net', 'testnet\n', 'a'.repeat(40), '-x']) {
            expect(status({ network: n }).networkValid, n).toBe(false);
        }
        for (const n of ['testnet', 'pubnet', 'futurenet', 'local-1']) {
            expect(status({ network: n }).networkValid, n).toBe(true);
        }
    });
});

describe('phase and badges', () => {
    it('pending without activate_at is pending', () => {
        const k = V.normalizeKey(PENDING());
        expect(V.phase(k, NOW)).toBe('pending');
        expect(V.keyBadge(k, NOW)).toEqual({ label: 'pending', cls: 'pending' });
    });

    it('pending with a future activate_at is scheduled', () => {
        const k = V.normalizeKey(key({ state: 'pending', activate_at: '2026-11-12T12:02:00Z' }));
        expect(V.phase(k, NOW)).toBe('scheduled');
        expect(V.keyBadge(k, NOW)).toEqual({ label: 'activation scheduled', cls: 'info' });
        expect(V.keyExplanation(k, NOW)).toContain('2026-11-12T12:02:00Z');
    });

    it('pending with a past activate_at is due (instances already switched)', () => {
        const k = V.normalizeKey(key({ state: 'pending', activate_at: '2026-11-12T11:59:00Z' }));
        expect(V.phase(k, NOW)).toBe('due');
        expect(V.keyBadge(k, NOW)).toEqual({ label: 'activating', cls: 'info' });
        expect(V.keyExplanation(k, NOW, true)).toContain('sign with it now');
        expect(V.keyExplanation(k, NOW)).toContain('sign with it now');
    });

    it('a scheduled or due key on a bridge with SEP-10 off waits for SEP-10 to be enabled', () => {
        // The swap is applied by the key rings, which run only while SEP-10 is
        // enabled. The documented first roll-out activates the key first.
        for (const at of ['2026-11-12T11:59:00Z', '2026-11-12T12:02:00Z']) {
            const k = V.normalizeKey(key({ state: 'pending', activate_at: at }));
            const text = V.keyExplanation(k, NOW, false);
            expect(text).toContain('SEP-10 is off on this bridge');
            expect(text).toContain('when SEP-10 is enabled');
            expect(text).toContain(at);
            expect(text).not.toContain('sign with it now');
        }
        // Unknown (an older payload without the field) keeps the usual wording.
        const due = V.normalizeKey(key({ state: 'pending', activate_at: '2026-11-12T11:59:00Z' }));
        expect(V.keyExplanation(due, NOW, null)).toContain('sign with it now');
        // Other phases do not depend on it.
        expect(V.keyExplanation(V.normalizeKey(ACTIVE()), NOW, false)).toContain('stellar.toml');
    });

    it('active, superseded and revoked rows', () => {
        expect(V.keyBadge(V.normalizeKey(ACTIVE()), NOW)).toEqual({ label: 'active', cls: 'ok' });
        expect(V.keyBadge(V.normalizeKey(key({ state: 'superseded', superseded_at: '2026-11-10T00:00:00Z' })), NOW))
            .toEqual({ label: 'superseded', cls: 'neutral' });
        expect(V.keyBadge(V.normalizeKey(key({ state: 'revoked', revoked_at: '2026-11-11T00:00:00Z' })), NOW))
            .toEqual({ label: 'revoked', cls: 'error' });
    });

    it('an unknown state renders neutrally with its raw name', () => {
        const k = V.normalizeKey(key({ state: 'quarantined' }));
        expect(k.knownState).toBeNull();
        expect(V.phase(k, NOW)).toBe('unknown');
        expect(V.keyBadge(k, NOW)).toEqual({ label: 'quarantined', cls: 'neutral' });
        expect(V.keyExplanation(k, NOW)).toContain('quarantined');
    });

    it('a missing state renders as unknown', () => {
        const k = V.normalizeKey({ version: 4 });
        expect(V.keyBadge(k, NOW)).toEqual({ label: 'unknown', cls: 'neutral' });
    });

    it('a state named like an Object.prototype member is not known', () => {
        const k = V.normalizeKey(key({ state: 'constructor' }));
        expect(k.knownState).toBeNull();
        expect(V.keyBadge(k, NOW).cls).toBe('neutral');
    });
});

describe('summary', () => {
    const texts = (sum) => sum.notices.map((n) => n.text).join(' | ');

    it('disabled: neutral badge and the SEP10_ENABLED notice', () => {
        const sum = V.summary(status({ enabled: false }), NOW);
        expect(sum.enabledBadge).toEqual({ label: 'disabled', cls: 'neutral' });
        expect(texts(sum)).toContain('SEP10_ENABLED=true');
        // Disabled with no key is not the 503 alarm: nothing is being served.
        expect(texts(sum)).not.toContain('503');
    });

    it('enabled with no key: alert that sign-in answers 503', () => {
        const sum = V.summary(status(), NOW);
        expect(sum.enabledBadge).toEqual({ label: 'enabled', cls: 'ok' });
        expect(sum.activeKey).toBeNull();
        expect(sum.notices.find((n) => n.text.includes('503')).cls).toBe('alert');
    });

    it('pending only: still no key in service', () => {
        const sum = V.summary(status({ keys: [PENDING()] }), NOW);
        expect(sum.pendingKey.version).toBe(2);
        expect(sum.activeKey).toBeNull();
        expect(texts(sum)).toContain('503');
    });

    it('a due activation is not reported as "no key"', () => {
        const sum = V.summary(status({
            keys: [key({ state: 'pending', activate_at: '2026-11-12T11:00:00Z' })]
        }), NOW);
        expect(texts(sum)).not.toContain('503');
    });

    it('active: the key in service, no alarm', () => {
        const sum = V.summary(status({ keys: [ACTIVE()] }), NOW);
        expect(sum.activeKey.fingerprint).toBe(FP_1);
        expect(sum.activeCount).toBe(1);
        expect(sum.notices).toEqual([]);
    });

    it('active + pending', () => {
        const sum = V.summary(status({ keys: [PENDING(), ACTIVE()] }), NOW);
        expect(sum.activeKey.version).toBe(1);
        expect(sum.pendingKey.version).toBe(2);
        expect(sum.notices).toEqual([]);
    });

    it('two active rows: alert, and no single key in service', () => {
        const sum = V.summary(status({ keys: [key({ version: 2, fingerprint: FP_2 }), ACTIVE()] }), NOW);
        expect(sum.activeKey).toBeNull();
        expect(sum.activeCount).toBe(2);
        expect(texts(sum)).toContain('2 active keys');
    });

    it('enabled but endpoint not configured', () => {
        const sum = V.summary(status({ keys: [ACTIVE()], home_domain: null, web_auth_endpoint: null }), NOW);
        expect(texts(sum)).toContain('not configured');
    });

    it('missing fields: not reported, and actions unavailable without a network', () => {
        const sum = V.summary(V.normalizeStatus({}), NOW);
        expect(sum.enabledBadge).toEqual({ label: 'not reported', cls: 'neutral' });
        expect(texts(sum)).toContain('no readable key list');
        expect(texts(sum)).toContain('network');
    });

    it('notice classes are callout classes only', () => {
        const all = [
            V.summary(V.normalizeStatus({}), NOW),
            V.summary(status({ enabled: false }), NOW),
            V.summary(status({ keys: [ACTIVE(), key({ version: 2 })] }), NOW)
        ].flatMap((s) => s.notices);
        for (const n of all) expect(['alert', 'warning', 'primary']).toContain(n.cls);
    });
});

describe('confirmation phrases', () => {
    it('activate: "activate sep10-signing {network}"', () => {
        expect(V.activatePhrase(status())).toBe('activate sep10-signing testnet');
        expect(V.activatePhrase(status({ network: 'pubnet' }))).toBe('activate sep10-signing pubnet');
    });

    it('revoke: "revoke sep10-signing {network} v{version}"', () => {
        const s = status({ keys: [ACTIVE()] });
        expect(V.revokePhrase(s, s.keys[0])).toBe('revoke sep10-signing testnet v1');
    });

    it('no phrase without a usable network or version', () => {
        const s = status({ network: undefined, keys: [ACTIVE()] });
        expect(V.activatePhrase(s)).toBeNull();
        expect(V.revokePhrase(s, s.keys[0])).toBeNull();
        const t = status({ keys: [key({ version: 0 })] });
        expect(V.revokePhrase(t, t.keys[0])).toBeNull();
    });
});

describe('what this bridge instance can serve (opened, key_ring_live)', () => {
    const pendingOpened = (opened) => Object.assign(PENDING(), { opened });
    const activeOpened = (opened) => Object.assign(ACTIVE(), { opened });

    it('reads opened and key_ring_live as tri-state; an older bridge reports neither', () => {
        const s = status({ key_ring_live: true, keys: [pendingOpened(false), activeOpened(true)] });
        expect(s.keyRingLive).toBe(true);
        expect(s.keys.map((k) => k.opened)).toEqual([false, true]);
        const old = status({ keys: [PENDING(), ACTIVE()] });
        expect(old.keyRingLive).toBe(null);
        expect(old.keys.map((k) => k.opened)).toEqual([null, null]);
        for (const junk of ['true', 1, 0, {}, undefined]) {
            expect(status({ key_ring_live: junk, keys: [pendingOpened(junk)] }).keyRingLive).toBe(null);
            expect(status({ keys: [pendingOpened(junk)] }).keys[0].opened).toBe(null);
        }
    });

    it('a pending key this instance has not opened cannot be activated yet, and says why', () => {
        const s = status({ key_ring_live: true, keys: [pendingOpened(false), activeOpened(true)] });
        expect(V.activationHold(s.keys[0]).held).toBe(true);
        expect(V.activationHold(s.keys[0]).reason).toContain('every 30 seconds');
        expect(V.actionsFor(s.keys[0], s, MANAGER, NOW)).toEqual({ activate: false, revoke: true });
        expect(V.keyExplanation(s.keys[0], NOW, true)).toContain('has not opened it yet');
        const r = V.buildActivate(s, s.keys[0], 'activate sep10-signing testnet');
        expect(r.ok).toBe(false);
        expect(r.error).toContain('has not opened it yet');
    });

    it('opened true, or not reported, does not hold activation', () => {
        for (const opened of [true, null, undefined]) {
            const s = status({ keys: [pendingOpened(opened), ACTIVE()] });
            expect(V.activationHold(s.keys[0]).held).toBe(false);
            expect(V.actionsFor(s.keys[0], s, MANAGER, NOW).activate).toBe(true);
            expect(V.buildActivate(s, s.keys[0], 'activate sep10-signing testnet').ok).toBe(true);
            expect(V.keyExplanation(s.keys[0], NOW, true)).not.toContain('has not opened');
        }
        // Only an unscheduled pending key is ever held.
        expect(V.activationHold(V.normalizeKey(activeOpened(false))).held).toBe(false);
        expect(V.activationHold(V.normalizeKey(Object.assign(pendingOpened(false), { activate_at: '2026-11-12T12:02:00Z' }))).held).toBe(false);
        expect(V.activationHold(null).held).toBe(false);
    });

    it('warns when the instance that answered cannot serve SEP-10', () => {
        const texts = (s) => V.summary(s, NOW).notices.map((n) => n.text).join(' | ');
        expect(texts(status({ key_ring_live: false, keys: [activeOpened(null)] }))).toContain('key ring of the bridge instance that answered is stale');
        expect(texts(status({ key_ring_live: true, keys: [activeOpened(false)] }))).toContain('could not open the active key (v1)');
        const healthy = texts(status({ key_ring_live: true, keys: [activeOpened(true)] }));
        expect(healthy).not.toContain('stale');
        expect(healthy).not.toContain('could not open');
        // With SEP-10 off there is no ring to be stale and nothing to open.
        const off = texts(status({ enabled: false, key_ring_live: null, keys: [activeOpened(null)] }));
        expect(off).not.toContain('stale');
        expect(off).not.toContain('could not open');
    });

    it('says in one line what the instance that answered can do', () => {
        const line = (s) => V.instanceLine(s, V.summary(s, NOW));
        expect(line(status({ key_ring_live: true, keys: [activeOpened(true)] }))).toBe('key ring live; the active key is open: serving SEP-10');
        // An older bridge reports the ring but not `opened`: nothing is claimed against it.
        expect(line(status({ key_ring_live: true, keys: [activeOpened(null)] }))).toContain('serving SEP-10');
        expect(line(status({ key_ring_live: true, keys: [activeOpened(false)] }))).toBe('key ring live, but the active key is not open here: answers 503');
        expect(line(status({ key_ring_live: true, keys: [pendingOpened(true)] }))).toBe('key ring live; no active key to serve');
        expect(line(status({ key_ring_live: true, keys: [] }))).toBe('key ring live; no active key to serve');
        // A stale ring wins over whatever it last held.
        expect(line(status({ key_ring_live: false, keys: [activeOpened(true)] }))).toBe('key ring stale: answers 503 for SEP-10');
        // No ring: SEP-10 off (keys can still be prepared), or a bridge that does not say.
        expect(line(status({ enabled: false, key_ring_live: null, keys: [activeOpened(null)] }))).toBe('runs no key ring (SEP-10 is off): keys are stored, not served');
        expect(line(status({ keys: [ACTIVE()] }))).toBe('did not report its key ring');
        expect(line(status({ enabled: null, key_ring_live: null, keys: [] }))).toBe('did not report its key ring');
    });

    it('explains a sep10_key_not_opened refusal from the bridge', () => {
        const e = Object.assign(new Error('This replica has not opened signing key version 2 yet.'), { status: 409, code: 'sep10_key_not_opened' });
        expect(V.actionErrorMessage(e)).toContain('was not activated');
        expect(V.actionErrorMessage(e)).toContain('every 30 seconds');
    });
});

describe('actionsFor', () => {
    const acts = (s, i, perms) => V.actionsFor(s.keys[i], s, perms, NOW);

    it('a viewer (auditor) gets no action on any key', () => {
        const s = status({ keys: [PENDING(), ACTIVE(), key({ version: 0, state: 'superseded' })] });
        for (let i = 0; i < s.keys.length; i++) {
            expect(acts(s, i, VIEWER)).toEqual({ activate: false, revoke: false });
        }
        expect(V.actionsFor(s.keys[0], s, undefined, NOW)).toEqual({ activate: false, revoke: false });
    });

    it('pending: activate and revoke', () => {
        const s = status({ keys: [PENDING(), ACTIVE()] });
        expect(acts(s, 0, MANAGER)).toEqual({ activate: true, revoke: true });
    });

    it('scheduled or due: revoke only (activation already requested)', () => {
        const s = status({ keys: [
            key({ version: 3, state: 'pending', activate_at: '2026-11-12T12:01:00Z' }),
            key({ version: 2, state: 'pending', activate_at: '2026-11-12T11:00:00Z' })
        ] });
        expect(acts(s, 0, MANAGER)).toEqual({ activate: false, revoke: true });
        expect(acts(s, 1, MANAGER)).toEqual({ activate: false, revoke: true });
    });

    it('active and superseded: revoke only', () => {
        const s = status({ keys: [ACTIVE(), key({ version: 0 }), key({ version: 5, state: 'superseded' })] });
        expect(acts(s, 0, MANAGER)).toEqual({ activate: false, revoke: true });
        expect(acts(s, 2, MANAGER)).toEqual({ activate: false, revoke: true });
    });

    it('revoked and unknown: nothing', () => {
        const s = status({ keys: [key({ state: 'revoked' }), key({ version: 2, state: 'mystery' })] });
        expect(acts(s, 0, MANAGER)).toEqual({ activate: false, revoke: false });
        expect(acts(s, 1, MANAGER)).toEqual({ activate: false, revoke: false });
    });

    it('nothing without a usable version or network', () => {
        const noVersion = status({ keys: [key({ version: null, state: 'pending', activate_at: null })] });
        expect(acts(noVersion, 0, MANAGER)).toEqual({ activate: false, revoke: false });
        const noNetwork = status({ network: 'Bad Word', keys: [PENDING()] });
        expect(acts(noNetwork, 0, MANAGER)).toEqual({ activate: false, revoke: false });
    });

    it('activation is withheld when the key to supersede is ambiguous', () => {
        const twoActive = status({ keys: [PENDING(), ACTIVE(), key({ version: 0 })] });
        // version 0 is unusable but the row still counts as active
        expect(acts(twoActive, 0, MANAGER)).toEqual({ activate: false, revoke: true });
        const noFp = status({ keys: [PENDING(), key({ fingerprint: null })] });
        expect(acts(noFp, 0, MANAGER)).toEqual({ activate: false, revoke: true });
    });
});

describe('canGenerate', () => {
    it('needs manage_keys', () => {
        expect(V.canGenerate(status(), VIEWER).allowed).toBe(false);
    });

    it('allowed with no pending key (even while SEP-10 is disabled)', () => {
        expect(V.canGenerate(status({ enabled: false }), MANAGER)).toEqual({ allowed: true, reason: '' });
        expect(V.canGenerate(status({ keys: [ACTIVE()] }), MANAGER).allowed).toBe(true);
    });

    it('refused while a pending key exists, naming it', () => {
        const g = V.canGenerate(status({ keys: [PENDING(), ACTIVE()] }), MANAGER);
        expect(g.allowed).toBe(false);
        expect(g.reason).toContain('v2');
    });

    it('generate request: POST .../generate with {}', () => {
        expect(V.buildGenerate()).toEqual({ path: '/admin/sep10/signing-keys/generate', body: {} });
    });
});

describe('buildActivate', () => {
    it('supersedes the active key by its fingerprint', () => {
        const s = status({ keys: [PENDING(), ACTIVE()] });
        const r = V.buildActivate(s, s.keys[0], 'activate sep10-signing testnet');
        expect(r).toEqual({
            ok: true,
            path: '/admin/sep10/signing-keys/2/activate',
            body: { confirm_supersede: FP_1, confirm_phrase: 'activate sep10-signing testnet' }
        });
    });

    it('supersedes "none" when no key is active', () => {
        const s = status({ keys: [PENDING(), key({ state: 'revoked' })] });
        const r = V.buildActivate(s, s.keys[0], 'activate sep10-signing testnet');
        expect(r.ok).toBe(true);
        expect(r.body.confirm_supersede).toBe('none');
    });

    it('accepts surrounding whitespace but sends the exact phrase', () => {
        const s = status({ keys: [PENDING()] });
        const r = V.buildActivate(s, s.keys[0], '  activate sep10-signing testnet \n');
        expect(r.body.confirm_phrase).toBe('activate sep10-signing testnet');
    });

    it('refuses a wrong or partial phrase, saying what to type', () => {
        const s = status({ keys: [PENDING()] });
        for (const typed of ['', 'activate sep10-signing', 'Activate sep10-signing testnet',
            'activate sep10-signing pubnet', 'activate  sep10-signing testnet', undefined]) {
            const r = V.buildActivate(s, s.keys[0], typed);
            expect(r.ok, String(typed)).toBe(false);
            expect(r.error).toBe('Type exactly: activate sep10-signing testnet');
        }
    });

    it('refuses a key that is not plain pending', () => {
        const s = status({ keys: [ACTIVE(), key({ version: 3, state: 'pending', activate_at: '2026-11-12T12:01:00Z' })] });
        expect(V.buildActivate(s, s.keys[0], 'activate sep10-signing testnet').ok).toBe(false);
        expect(V.buildActivate(s, s.keys[1], 'activate sep10-signing testnet').ok).toBe(false);
    });

    it('refuses when the supersede target is ambiguous', () => {
        const s = status({ keys: [PENDING(), ACTIVE(), key({ version: 7, fingerprint: FP_2 })] });
        const r = V.buildActivate(s, s.keys[0], 'activate sep10-signing testnet');
        expect(r.ok).toBe(false);
        expect(r.error).toMatch(/more than one/i);
    });

    it('refuses without a network', () => {
        const s = status({ network: null, keys: [PENDING()] });
        expect(V.buildActivate(s, s.keys[0], 'activate sep10-signing null').ok).toBe(false);
    });
});

describe('buildRevoke', () => {
    it('builds the revoke request for the active key', () => {
        const s = status({ keys: [ACTIVE()] });
        expect(V.buildRevoke(s, s.keys[0], 'revoke sep10-signing testnet v1')).toEqual({
            ok: true,
            path: '/admin/sep10/signing-keys/1/revoke',
            body: { confirm_phrase: 'revoke sep10-signing testnet v1' }
        });
    });

    it('the phrase names the exact version', () => {
        const s = status({ keys: [PENDING(), ACTIVE()] });
        expect(V.buildRevoke(s, s.keys[0], 'revoke sep10-signing testnet v1').ok).toBe(false);
        expect(V.buildRevoke(s, s.keys[0], 'revoke sep10-signing testnet v2').ok).toBe(true);
    });

    it('refuses revoked and unknown keys', () => {
        const s = status({ keys: [key({ state: 'revoked' }), key({ version: 2, state: 'mystery' })] });
        expect(V.buildRevoke(s, s.keys[0], 'revoke sep10-signing testnet v1').ok).toBe(false);
        expect(V.buildRevoke(s, s.keys[1], 'revoke sep10-signing testnet v2').ok).toBe(false);
    });

    it('warns that revoking the active key stops SEP-10 sign-in', () => {
        const w = V.revokeWarning(V.normalizeKey(ACTIVE()), NOW);
        expect(w.severity).toBe('alert');
        expect(w.text).toContain('stops SEP-10 sign-in');
        const due = V.revokeWarning(V.normalizeKey(key({ state: 'pending', activate_at: '2026-11-12T11:00:00Z' })), NOW);
        expect(due.severity).toBe('alert');
    });

    it('other phases get a warning, not the alert', () => {
        for (const k of [PENDING(), key({ state: 'superseded' }),
            key({ state: 'pending', activate_at: '2026-11-12T13:00:00Z' })]) {
            expect(V.revokeWarning(V.normalizeKey(k), NOW).severity).toBe('warning');
        }
    });
});

describe('load errors (deploy skew)', () => {
    const err = (status, message, code) => Object.assign(new Error(message || 'x'), { status, code: code || null });

    it('404 means an older bridge: neutral "not offered", not an error', () => {
        expect(V.classifyLoadError(err(404, 'Not found'))).toEqual({
            kind: 'unsupported', message: 'This bridge does not offer SEP-10.'
        });
    });

    it('403 and other failures', () => {
        expect(V.classifyLoadError(err(403)).kind).toBe('forbidden');
        expect(V.classifyLoadError(err(500, 'Server error'))).toEqual({ kind: 'error', message: 'Server error' });
        expect(V.classifyLoadError(new Error('Bridge unavailable, please retry')).kind).toBe('error');
        expect(V.classifyLoadError(undefined).kind).toBe('error');
    });
});

describe('action messages', () => {
    it('maps pending_key_exists', () => {
        const e = Object.assign(new Error('A pending key exists'), { status: 409, code: 'pending_key_exists' });
        expect(V.actionErrorMessage(e)).toMatch(/pending key already exists/);
    });

    it('passes other bridge messages through', () => {
        const e = Object.assign(new Error('confirm_supersede does not match'), { status: 409, code: 'conflict' });
        expect(V.actionErrorMessage(e)).toBe('confirm_supersede does not match');
    });

    it('describes generate / activate / revoke responses, tolerating gaps', () => {
        expect(V.describeGenerated({ version: 2, state: 'pending', public_address: ADDR_2, fingerprint: FP_2 }))
            .toBe('Generated signing key v2 (pending): ' + ADDR_2 + '. It signs nothing until you activate it.');
        expect(V.describeGenerated(null)).toContain('(pending)');
        expect(V.describeActivated({ version: 2, state: 'pending', activate_at: '2026-11-12T12:02:00Z' }))
            .toBe('Signing key v2 takes over at 2026-11-12T12:02:00Z.');
        expect(V.describeActivated({})).toContain('activation delay');
        expect(V.describeRevoked({ version: 1, state: 'revoked' })).toBe('Signing key v1 revoked.');
    });

    it('formats the challenge lifetime', () => {
        expect(V.formatTtl(300)).toBe('300 s (5 min)');
        expect(V.formatTtl(45)).toBe('45 s');
        expect(V.formatTtl(null)).toBe('not reported');
    });
});
