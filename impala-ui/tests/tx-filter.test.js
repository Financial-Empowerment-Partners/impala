import { describe, it, expect, beforeAll } from 'vitest';
import { loadScript } from './helpers/load-script.js';

let TxFilter;
beforeAll(() => {
    TxFilter = loadScript('tx-filter.js', 'TxFilter');
});

// Parse a query string back into an object for order-independent assertions.
function parse(qs) {
    const out = {};
    if (!qs) return out;
    qs.split('&').forEach((pair) => {
        const [k, v] = pair.split('=');
        out[decodeURIComponent(k)] = decodeURIComponent(v);
    });
    return out;
}

describe('TxFilter.buildQuery', () => {
    it('returns an empty string for no filters', () => {
        expect(TxFilter.buildQuery()).toBe('');
        expect(TxFilter.buildQuery({})).toBe('');
    });

    it('includes pagination params', () => {
        expect(parse(TxFilter.buildQuery({ page: 2, per_page: 10 }))).toEqual({ page: '2', per_page: '10' });
    });

    it('includes status when set', () => {
        expect(parse(TxFilter.buildQuery({ status: 'flagged' })).status).toBe('flagged');
    });

    it('handles flagged=true (boolean and string)', () => {
        expect(parse(TxFilter.buildQuery({ flagged: true })).flagged).toBe('true');
        expect(parse(TxFilter.buildQuery({ flagged: 'true' })).flagged).toBe('true');
    });

    it('handles flagged=false (boolean and string)', () => {
        expect(parse(TxFilter.buildQuery({ flagged: false })).flagged).toBe('false');
        expect(parse(TxFilter.buildQuery({ flagged: 'false' })).flagged).toBe('false');
    });

    it('omits flagged when blank', () => {
        expect(parse(TxFilter.buildQuery({ flagged: '' })).flagged).toBeUndefined();
    });

    it('trims and includes text filters', () => {
        const q = parse(TxFilter.buildQuery({ q: '  hello  ', source_account: ' GABC ' }));
        expect(q.q).toBe('hello');
        expect(q.source_account).toBe('GABC');
    });

    it('omits empty text filters', () => {
        const q = parse(TxFilter.buildQuery({ q: '   ', source_account: '' }));
        expect(q.q).toBeUndefined();
        expect(q.source_account).toBeUndefined();
    });

    it('includes from/to range', () => {
        const q = parse(TxFilter.buildQuery({ from: '2026-01-01T00:00:00Z', to: '2026-02-01T23:59:59Z' }));
        expect(q.from).toBe('2026-01-01T00:00:00Z');
        expect(q.to).toBe('2026-02-01T23:59:59Z');
    });

    it('URL-encodes special characters', () => {
        const raw = TxFilter.buildQuery({ q: 'a&b=c' });
        expect(raw).toBe('q=a%26b%3Dc');
        expect(parse(raw).q).toBe('a&b=c');
    });
});
