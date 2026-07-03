import { describe, it, expect, beforeAll } from 'vitest';
import { loadScript } from './helpers/load-script.js';

let Validate;
beforeAll(() => {
    Validate = loadScript('validate.js', 'Validate');
});

describe('Validate.stellarId', () => {
    it('rejects empty input', () => {
        const r = Validate.stellarId('');
        expect(r.valid).toBe(false);
        expect(r.message).toMatch(/required/i);
    });

    it('rejects IDs not starting with G', () => {
        const id = 'A' + 'B'.repeat(55);
        const r = Validate.stellarId(id);
        expect(r.valid).toBe(false);
        expect(r.message).toMatch(/start with G/i);
    });

    it('rejects IDs of wrong length', () => {
        const r = Validate.stellarId('GSHORT');
        expect(r.valid).toBe(false);
        expect(r.message).toMatch(/56/);
    });

    it('rejects non-alphanumeric characters', () => {
        const id = 'G' + '!'.repeat(55);
        const r = Validate.stellarId(id);
        expect(r.valid).toBe(false);
    });

    it('accepts a 56-char alphanumeric ID starting with G', () => {
        const id = 'G' + 'A'.repeat(55);
        const r = Validate.stellarId(id);
        expect(r.valid).toBe(true);
    });

    it('trims whitespace before validating', () => {
        const id = '  G' + 'A'.repeat(55) + '  ';
        const r = Validate.stellarId(id);
        expect(r.valid).toBe(true);
    });
});

describe('Validate.phone', () => {
    it('rejects empty input', () => {
        expect(Validate.phone('').valid).toBe(false);
    });

    it('rejects numbers without leading +', () => {
        expect(Validate.phone('12345678').valid).toBe(false);
    });

    it('accepts valid E.164 numbers', () => {
        expect(Validate.phone('+15551234567').valid).toBe(true);
    });

    it('rejects numbers that are too short', () => {
        expect(Validate.phone('+1234').valid).toBe(false);
    });

    it('rejects numbers that are too long', () => {
        expect(Validate.phone('+1234567890123456').valid).toBe(false);
    });
});

describe('Validate.email', () => {
    it('rejects empty input', () => {
        expect(Validate.email('').valid).toBe(false);
    });

    it('rejects strings without @', () => {
        expect(Validate.email('notanemail.com').valid).toBe(false);
    });

    it('rejects strings without a TLD', () => {
        expect(Validate.email('foo@bar').valid).toBe(false);
    });

    it('accepts a basic email', () => {
        expect(Validate.email('a@b.co').valid).toBe(true);
    });
});
