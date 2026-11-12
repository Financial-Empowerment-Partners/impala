import { describe, it, expect, beforeAll } from 'vitest';
import { loadScript } from './helpers/load-script.js';

// Validate.stellarAccountId is the full StrKey (SEP-23) check used before a
// card's Stellar address is sent to the bridge: length, alphabet, version
// byte and CRC16-XModem checksum.
let Validate;
beforeAll(() => {
    Validate = loadScript('validate.js', 'Validate');
});

// SEP-23 account-id vector. Verified independently while writing this suite:
// it base32-decodes to 35 bytes, version 0x30, key
// 3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a, and the
// CRC16-XModem of the first 33 bytes is 0xd9c8, stored little-endian (c8 d9).
const SEP23 = 'GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ';
// The all-zero ed25519 key as an account id.
const ZERO_KEY = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
// Same 32-byte key as SEP23 under other version bytes, each with a CORRECT
// checksum, so only the version check can reject them.
const SAME_KEY_VERSION_0x31 = 'GE7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUFCU';
const SAME_KEY_AS_SEED = 'SA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWVG';

describe('Validate.crc16Xmodem', () => {
    it('matches the XModem check value for "123456789" (0x31c3)', () => {
        const bytes = Array.from('123456789', (c) => c.charCodeAt(0));
        expect(Validate.crc16Xmodem(bytes, bytes.length)).toBe(0x31c3);
    });
});

describe('Validate.stellarAccountId', () => {
    it('accepts the SEP-23 account vector', () => {
        expect(Validate.stellarAccountId(SEP23)).toEqual({ valid: true, message: '' });
    });

    it('accepts the all-zero key address', () => {
        expect(Validate.stellarAccountId(ZERO_KEY).valid).toBe(true);
    });

    it('trims surrounding whitespace', () => {
        expect(Validate.stellarAccountId('  ' + SEP23 + '\n').valid).toBe(true);
    });

    it('requires a value', () => {
        for (const v of ['', '   ', null, undefined, 42]) {
            const r = Validate.stellarAccountId(v);
            expect(r.valid).toBe(false);
            expect(r.message).toMatch(/required/i);
        }
    });

    it('rejects the wrong length', () => {
        expect(Validate.stellarAccountId(SEP23.slice(0, 55)).message).toMatch(/56/);
        expect(Validate.stellarAccountId(SEP23 + 'A').message).toMatch(/56/);
    });

    it('rejects lowercase', () => {
        const r = Validate.stellarAccountId(SEP23.toLowerCase());
        expect(r.valid).toBe(false);
        expect(r.message).toMatch(/upper-case/);
    });

    it('rejects characters outside the base32 alphabet (0, 1, 8, 9, punctuation)', () => {
        for (const bad of ['0', '1', '8', '9', '=', '-']) {
            const v = SEP23.slice(0, 20) + bad + SEP23.slice(21);
            const r = Validate.stellarAccountId(v);
            expect(r.valid, bad).toBe(false);
            expect(r.message).toMatch(/A-Z and digits 2-7/);
        }
    });

    it('rejects the wrong version byte even with a valid checksum', () => {
        const r = Validate.stellarAccountId(SAME_KEY_VERSION_0x31);
        expect(r.valid).toBe(false);
        expect(r.message).toMatch(/version byte/);
        expect(Validate.stellarAccountId(SAME_KEY_AS_SEED).message).toMatch(/version byte/);
    });

    it('rejects a bad checksum (one character changed)', () => {
        const v = SEP23.slice(0, 10) + (SEP23[10] === 'A' ? 'B' : 'A') + SEP23.slice(11);
        const r = Validate.stellarAccountId(v);
        expect(r.valid).toBe(false);
        expect(r.message).toMatch(/checksum/);
    });

    it('rejects a bad checksum (checksum characters changed)', () => {
        const r = Validate.stellarAccountId(SEP23.slice(0, 54) + 'AA');
        expect(r.valid).toBe(false);
        expect(r.message).toMatch(/checksum/);
    });

    it('rejects every single-character substitution of the vector', () => {
        // CRC16 detects all single-symbol errors in a message this short; the
        // version check catches the ones in the leading characters.
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        for (let i = 0; i < SEP23.length; i++) {
            for (const c of alphabet) {
                if (c === SEP23[i]) continue;
                const v = SEP23.slice(0, i) + c + SEP23.slice(i + 1);
                expect(Validate.stellarAccountId(v).valid, `${i}:${c}`).toBe(false);
            }
        }
    });

    it('leaves the old shape-only stellarId check unchanged', () => {
        // stellarId is used by the account forms; it is not a checksum check.
        expect(Validate.stellarId('G' + 'A'.repeat(55)).valid).toBe(true);
        expect(Validate.stellarAccountId('G' + 'A'.repeat(55)).valid).toBe(false);
    });
});
