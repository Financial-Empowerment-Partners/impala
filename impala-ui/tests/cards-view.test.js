import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { loadScripts } from './helpers/load-script.js';

// cards-view.js builds the POST /card body (with the optional SEP-10
// Stellar-key group, docs/sep10-card-keys.md section 6) and models the
// Accounts drawer's card list. It depends on Validate, loaded first exactly
// as the <script> order does.
let CardsView;
beforeAll(() => {
    ({ CardsView } = loadScripts(['validate.js', 'cards-view.js'], ['Validate', 'CardsView']));
});

const ADDR = 'GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ';
// A plausible 70-byte DER ECDSA signature: 30 44 02 20 <32> 02 20 <32>.
const DER = '3044' + '0220' + '11'.repeat(32) + '0220' + '22'.repeat(32);
const PROOF = 'ab'.repeat(64);

const BASE = {
    accountId: '7f3c2a10-5b6d-4e8f-9a01-23456789abcd',
    cardId: '00112233445566778899aabbccddeeff',
    ecPubkey: '04' + 'cd'.repeat(64),
    rsaPubkey: ''
};

function input(overrides) {
    return Object.assign({}, BASE, overrides || {});
}

describe('buildRegistration without the Stellar group', () => {
    it('is byte-identical to the pre-SEP-10 body', () => {
        const r = CardsView.buildRegistration(input());
        expect(r.ok).toBe(true);
        // The literal the page built before this change.
        const legacy = {
            account_id: BASE.accountId,
            card_id: BASE.cardId,
            ec_pubkey: BASE.ecPubkey,
            rsa_pubkey: BASE.rsaPubkey || undefined
        };
        expect(JSON.stringify(r.body)).toBe(JSON.stringify(legacy));
        expect(JSON.stringify(r.body)).toBe(
            '{"account_id":"' + BASE.accountId + '","card_id":"' + BASE.cardId +
            '","ec_pubkey":"' + BASE.ecPubkey + '"}');
    });

    it('keeps rsa_pubkey when given, in the same position', () => {
        const r = CardsView.buildRegistration(input({ rsaPubkey: 'abcd' }));
        expect(Object.keys(r.body)).toEqual(['account_id', 'card_id', 'ec_pubkey', 'rsa_pubkey']);
    });

    it('treats whitespace-only Stellar fields as absent', () => {
        const r = CardsView.buildRegistration(input({
            stellarAddress: '  ', stellarBindingSig: '\t', stellarProofSig: ''
        }));
        expect(r.ok).toBe(true);
        expect(Object.keys(r.body)).toEqual(['account_id', 'card_id', 'ec_pubkey', 'rsa_pubkey']);
        expect(JSON.stringify(r.body)).not.toContain('stellar');
    });

    it('keeps the existing validation messages', () => {
        expect(CardsView.buildRegistration(input({ accountId: ' ' })).error).toBe('This field is required');
        expect(CardsView.buildRegistration(input({ ecPubkey: 'xyz' })).error)
            .toBe('Must contain only hex characters (0-9, a-f)');
        expect(CardsView.buildRegistration(input({ rsaPubkey: 'abc' })).error)
            .toBe('RSA public key: Hex string must have an even number of characters');
    });
});

describe('buildRegistration with the Stellar group', () => {
    it('appends the three fields after the legacy ones', () => {
        const r = CardsView.buildRegistration(input({
            stellarAddress: ADDR, stellarBindingSig: DER, stellarProofSig: PROOF
        }));
        expect(r.ok).toBe(true);
        expect(Object.keys(r.body)).toEqual([
            'account_id', 'card_id', 'ec_pubkey', 'rsa_pubkey',
            'stellar_address', 'stellar_binding_sig', 'stellar_proof_sig'
        ]);
        expect(r.body.stellar_address).toBe(ADDR);
        expect(r.body.stellar_binding_sig).toBe(DER);
        expect(r.body.stellar_proof_sig).toBe(PROOF);
    });

    it('sends the signatures as lowercase hex, trimmed', () => {
        const r = CardsView.buildRegistration(input({
            stellarAddress: ' ' + ADDR + ' ',
            stellarBindingSig: DER.toUpperCase() + ' ',
            stellarProofSig: ' ' + PROOF.toUpperCase()
        }));
        expect(r.body.stellar_address).toBe(ADDR);
        expect(r.body.stellar_binding_sig).toBe(DER);
        expect(r.body.stellar_proof_sig).toBe(PROOF);
    });

    it('legacy validation runs first', () => {
        const r = CardsView.buildRegistration(input({
            cardId: '', stellarAddress: ADDR, stellarBindingSig: DER, stellarProofSig: PROOF
        }));
        expect(r.error).toBe('This field is required');
    });
});

describe('stellarFields: all three or none', () => {
    const full = { address: ADDR, bindingSig: DER, proofSig: PROOF };

    it('none present', () => {
        expect(CardsView.stellarFields({})).toEqual({ ok: true, present: false });
        expect(CardsView.stellarFields(undefined)).toEqual({ ok: true, present: false });
    });

    it('all present and valid', () => {
        const r = CardsView.stellarFields(full);
        expect(r.ok).toBe(true);
        expect(r.present).toBe(true);
    });

    it.each([
        ['address only', { address: ADDR }],
        ['binding only', { bindingSig: DER }],
        ['proof only', { proofSig: PROOF }],
        ['address + binding', { address: ADDR, bindingSig: DER }],
        ['address + proof', { address: ADDR, proofSig: PROOF }],
        ['binding + proof', { bindingSig: DER, proofSig: PROOF }]
    ])('refuses a partial group: %s', (_, partial) => {
        const r = CardsView.stellarFields(partial);
        expect(r.ok).toBe(false);
        expect(r.error).toMatch(/all three/);
    });

    it('refuses a partial group through buildRegistration too (nothing is sent)', () => {
        const r = CardsView.buildRegistration(input({ stellarAddress: ADDR }));
        expect(r.ok).toBe(false);
        expect(r.body).toBeUndefined();
    });

    it('checks the address with the StrKey checksum', () => {
        const bad = ADDR.slice(0, 55) + (ADDR[55] === 'A' ? 'B' : 'A');
        const r = CardsView.stellarFields({ ...full, address: bad });
        expect(r.ok).toBe(false);
        expect(r.error).toMatch(/^Stellar address: .*checksum/);
        expect(CardsView.stellarFields({ ...full, address: ADDR.toLowerCase() }).error)
            .toMatch(/^Stellar address: /);
    });

    it('binding signature: 16 to 144 hex characters, even', () => {
        expect(CardsView.stellarFields({ ...full, bindingSig: '30'.repeat(8) }).ok).toBe(true);   // 16
        expect(CardsView.stellarFields({ ...full, bindingSig: '3046' + 'ab'.repeat(70) }).ok).toBe(true); // 144
        expect(CardsView.stellarFields({ ...full, bindingSig: 'ab'.repeat(7) }).error).toMatch(/16 to 144/);
        expect(CardsView.stellarFields({ ...full, bindingSig: 'ab'.repeat(73) }).error).toMatch(/16 to 144/);
        expect(CardsView.stellarFields({ ...full, bindingSig: DER + 'a' }).error).toMatch(/even/);
        expect(CardsView.stellarFields({ ...full, bindingSig: DER.slice(0, 20) + 'zz' + DER.slice(22) }).error)
            .toMatch(/hex characters/);
    });

    it('binding signature: spots the zero-padded 72-byte slot and says how much to keep', () => {
        const padded = DER + '00'.repeat(72 - DER.length / 2);
        expect(padded.length).toBe(144);
        const r = CardsView.stellarFields({ ...full, bindingSig: padded });
        expect(r.ok).toBe(false);
        expect(r.error).toContain('first ' + DER.length + ' hex characters');
    });

    it('proof signature: exactly 128 hex characters', () => {
        expect(CardsView.stellarFields({ ...full, proofSig: PROOF.slice(2) }).error).toMatch(/exactly 128/);
        expect(CardsView.stellarFields({ ...full, proofSig: PROOF + 'ab' }).error).toMatch(/exactly 128/);
        expect(CardsView.stellarFields({ ...full, proofSig: 'g' + PROOF.slice(1) }).error).toMatch(/exactly 128/);
    });
});

describe('registrationErrorMessage', () => {
    const err = (status, code, message) => Object.assign(new Error(message || 'refused'), { status, code });

    it('maps invalid_stellar_binding (400)', () => {
        expect(CardsView.registrationErrorMessage(err(400, 'invalid_stellar_binding')))
            .toMatch(/could not verify the Stellar key's cross-signatures/);
    });

    it('maps stellar_address_in_use (409)', () => {
        expect(CardsView.registrationErrorMessage(err(409, 'stellar_address_in_use')))
            .toMatch(/already registered on another active card/);
    });

    it('falls back to the code in the message when the envelope had none', () => {
        expect(CardsView.registrationErrorMessage(err(409, null, 'stellar_address_in_use')))
            .toMatch(/already registered/);
    });

    it('does not mistake a generic conflict for the Stellar one', () => {
        expect(CardsView.registrationErrorMessage(err(409, 'conflict', 'Card already registered')))
            .toBe('Error: Card already registered');
        expect(CardsView.registrationErrorMessage(err(403, 'forbidden', 'Access denied')))
            .toBe('Error: Access denied');
    });
});

describe('card list (Accounts drawer)', () => {
    it('normalises the documented card objects', () => {
        const list = CardsView.normalizeCardList({
            cards: [
                { card_id: 'c2', active: true, created_at: '2026-11-12T10:00:00Z', deleted_at: null, stellar_address: ADDR },
                { card_id: 'c1', active: false, created_at: '2026-10-01T10:00:00Z', deleted_at: '2026-11-01T10:00:00Z', stellar_address: null }
            ]
        });
        expect(list.malformed).toBe(false);
        expect(list.cards[0]).toEqual({
            cardId: 'c2', status: { label: 'active', cls: 'ok' },
            createdAt: '2026-11-12T10:00:00Z', deletedAt: null,
            stellarAddress: ADDR, sep10: true
        });
        expect(list.cards[1]).toMatchObject({
            cardId: 'c1', status: { label: 'deleted', cls: 'neutral' },
            deletedAt: '2026-11-01T10:00:00Z', stellarAddress: null, sep10: false
        });
    });

    it('a malformed address is shown but not badged SEP-10', () => {
        const row = CardsView.cardRow({ card_id: 'c', active: true, stellar_address: 'GBAD' });
        expect(row.stellarAddress).toBe('GBAD');
        expect(row.sep10).toBe(false);
    });

    it('tolerates missing fields and an unreadable payload', () => {
        expect(CardsView.cardRow(null)).toMatchObject({
            cardId: null, status: { label: 'unknown', cls: 'neutral' }, stellarAddress: null, sep10: false
        });
        expect(CardsView.cardRow({ active: 'yes' }).status.label).toBe('unknown');
        for (const p of [null, {}, { cards: 'x' }, []]) {
            expect(CardsView.normalizeCardList(p)).toEqual({ cards: [], malformed: true });
        }
    });

    it('SEP-10 is refused for exactly the roles that hold a bridge capability', () => {
        // The bridge derives "privileged" from its capability matrix, which
        // is asserted against this same fixture: both sides follow the file.
        const fixture = JSON.parse(readFileSync(
            new URL('./fixtures/role-capabilities.json', import.meta.url), 'utf8'));
        const holders = new Set(Object.values(fixture.capabilities).flat());
        expect([...CardsView.SEP10_REFUSED_ROLES].sort()).toEqual([...holders].sort());
        for (const role of fixture.roles) {
            expect(CardsView.sep10RefusedFor(role, false)).toBe(holders.has(role));
        }
        // An allowlisted account is an effective admin whatever its stored role.
        expect(CardsView.sep10RefusedFor('view-only', true)).toBe(true);
        // Unknown or missing roles are not presumed refused (display only).
        for (const role of ['superuser', 'constructor', '', null, undefined]) {
            expect(CardsView.sep10RefusedFor(role, false)).toBe(false);
        }
    });

    it('status classes are a fixed set', () => {
        for (const active of [true, false, null, 'x']) {
            expect(['ok', 'neutral']).toContain(CardsView.cardRow({ active }).status.cls);
        }
    });

    it('a router 404 (no envelope) means an older bridge; a handler 404 is shown', () => {
        const routerMiss = Object.assign(new Error('Not found'), { status: 404, code: null });
        expect(CardsView.classifyCardListError(routerMiss).kind).toBe('unsupported');
        const handler = Object.assign(new Error('Account not found'), { status: 404, code: 'not_found' });
        expect(CardsView.classifyCardListError(handler)).toEqual({ kind: 'error', message: 'Account not found' });
        expect(CardsView.classifyCardListError(Object.assign(new Error('x'), { status: 403 })).kind).toBe('forbidden');
    });
});
