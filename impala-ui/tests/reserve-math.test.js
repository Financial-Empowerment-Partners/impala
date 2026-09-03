import { describe, it, expect, beforeAll } from 'vitest';
import { loadScript } from './helpers/load-script.js';

// reserve-math.js is DOM-free by design so the money formatting, threshold
// validation, and chart geometry are testable exactly like validate.js.
let ReserveMath;
beforeAll(() => {
    ReserveMath = loadScript('reserve-math.js', 'ReserveMath');
});

describe('minorToDecimal', () => {
    it('renders minor units exactly, without floats', () => {
        expect(ReserveMath.minorToDecimal(255000000, 7)).toBe('25.5000000');
        expect(ReserveMath.minorToDecimal(1, 7)).toBe('0.0000001');
        expect(ReserveMath.minorToDecimal(0, 7)).toBe('0.0000000');
        expect(ReserveMath.minorToDecimal(1234, 2)).toBe('12.34');
        expect(ReserveMath.minorToDecimal(-1234, 2)).toBe('-12.34');
        expect(ReserveMath.minorToDecimal(2000, 0)).toBe('2000');
    });
});

describe('display', () => {
    it('trims trailing zeros but keeps significant precision', () => {
        expect(ReserveMath.display(2000000000, 7)).toBe('200');
        expect(ReserveMath.display(255000000, 7)).toBe('25.50');
        expect(ReserveMath.display(255000001, 7)).toBe('25.5000001');
        expect(ReserveMath.display(1234, 2)).toBe('12.34');
    });

    it('adds thousands separators', () => {
        expect(ReserveMath.display(12345670000000, 7)).toBe('1,234,567');
        expect(ReserveMath.display(-12345670000000, 7)).toBe('-1,234,567');
    });
});

describe('centsToUsd', () => {
    it('formats cents as dollars', () => {
        expect(ReserveMath.centsToUsd(2000)).toBe('$20.00');
        expect(ReserveMath.centsToUsd(20000)).toBe('$200.00');
        expect(ReserveMath.centsToUsd(12345)).toBe('$123.45');
        expect(ReserveMath.centsToUsd(5)).toBe('$0.05');
        expect(ReserveMath.centsToUsd(-150)).toBe('-$1.50');
        expect(ReserveMath.centsToUsd(123456789)).toBe('$1,234,567.89');
    });
});

describe('fmtDelta', () => {
    it('signs ledger deltas', () => {
        expect(ReserveMath.fmtDelta(255000000, 7)).toBe('+25.50');
        expect(ReserveMath.fmtDelta(-255000000, 7)).toBe('−25.50');
        expect(ReserveMath.fmtDelta(0, 7)).toBe('0');
    });
});

describe('validateThresholdDollars', () => {
    it('mirrors the server band: $20 to $200 inclusive', () => {
        expect(ReserveMath.validateThresholdDollars('20')).toEqual({ ok: true, cents: 2000, error: null });
        expect(ReserveMath.validateThresholdDollars('200')).toEqual({ ok: true, cents: 20000, error: null });
        expect(ReserveMath.validateThresholdDollars('150.50').cents).toBe(15050);
        expect(ReserveMath.validateThresholdDollars('19.99').ok).toBe(false);
        expect(ReserveMath.validateThresholdDollars('200.01').ok).toBe(false);
    });

    it('rejects junk without throwing', () => {
        for (const bad of ['', '  ', 'abc', '-20', '20.123', '1e3', null, undefined]) {
            expect(ReserveMath.validateThresholdDollars(bad).ok).toBe(false);
        }
    });
});

describe('validateAmount', () => {
    it('parses display units into integer minor units', () => {
        expect(ReserveMath.validateAmount('25.5', 7)).toEqual({ ok: true, minor: 255000000, error: null });
        expect(ReserveMath.validateAmount('0.0000001', 7).minor).toBe(1);
        expect(ReserveMath.validateAmount('12.34', 2).minor).toBe(1234);
        expect(ReserveMath.validateAmount('100', 0).minor).toBe(100);
    });

    it('rejects zero, negatives, excess precision and junk', () => {
        expect(ReserveMath.validateAmount('0', 7).ok).toBe(false);
        expect(ReserveMath.validateAmount('-5', 7).ok).toBe(false);
        expect(ReserveMath.validateAmount('1.001', 2).ok).toBe(false);
        expect(ReserveMath.validateAmount('1.5.2', 7).ok).toBe(false);
        expect(ReserveMath.validateAmount('', 7).ok).toBe(false);
    });
});

describe('depletionBadge', () => {
    it('maps projected days onto badge classes', () => {
        expect(ReserveMath.depletionBadge(null)).toBe('neutral');
        expect(ReserveMath.depletionBadge(undefined)).toBe('neutral');
        expect(ReserveMath.depletionBadge(3)).toBe('error');
        expect(ReserveMath.depletionBadge(7)).toBe('error');
        expect(ReserveMath.depletionBadge(8)).toBe('pending');
        expect(ReserveMath.depletionBadge(30)).toBe('pending');
        expect(ReserveMath.depletionBadge(31)).toBe('ok');
    });
});

describe('refundBadge', () => {
    it('flags anything waiting on a human as red', () => {
        // Both mean customer money is stuck, not that a request errored.
        expect(ReserveMath.refundBadge('frozen')).toBe('error');
        expect(ReserveMath.refundBadge('failed')).toBe('error');
    });

    it('maps the rest of the lifecycle', () => {
        expect(ReserveMath.refundBadge('sent')).toBe('ok');
        expect(ReserveMath.refundBadge('needs_review')).toBe('pending');
        expect(ReserveMath.refundBadge('queued')).toBe('neutral');
        expect(ReserveMath.refundBadge('inflight')).toBe('neutral');
        expect(ReserveMath.refundBadge('cancelled')).toBe('neutral');
        expect(ReserveMath.refundBadge('nonsense')).toBe('neutral');
    });
});

describe('cycleBadge', () => {
    it('shows in-transit fiat as unconfirmed, not complete', () => {
        // The provider says it paid; nobody has seen the bank credit. Green
        // here would claim money the bridge cannot verify.
        expect(ReserveMath.cycleBadge('in_transit')).toBe('pending');
        expect(ReserveMath.cycleBadge('completed')).toBe('ok');
    });

    it('maps the rest of the cycle states', () => {
        expect(ReserveMath.cycleBadge('frozen')).toBe('error');
        expect(ReserveMath.cycleBadge('failed')).toBe('error');
        for (const s of ['planned', 'creating', 'created', 'sending', 'sent', 'settled', 'refunded']) {
            expect(ReserveMath.cycleBadge(s)).toBe('neutral');
        }
    });
});

describe('chartData', () => {
    const daily = [
        { day: '2026-08-18', outflow_minor: 100, inflow_minor: 0 },
        { day: '2026-08-19', outflow_minor: 200, inflow_minor: 50 },
        { day: '2026-08-20', outflow_minor: 0, inflow_minor: 200 },
    ];

    it('scales bars to the max flow and keeps one bar per day', () => {
        const geo = ReserveMath.chartData(daily, 300, 100);
        expect(geo.bars).toHaveLength(3);
        expect(geo.max).toBe(200);
        // The tallest outflow reaches (nearly) full height; zero stays flat.
        expect(geo.bars[1].h).toBeGreaterThan(geo.bars[0].h);
        expect(geo.bars[2].h).toBe(0);
        // Bars stay inside the viewBox.
        for (const b of geo.bars) {
            expect(b.x).toBeGreaterThanOrEqual(0);
            expect(b.x + b.w).toBeLessThanOrEqual(300);
            expect(b.y + b.h).toBe(100);
        }
    });

    it('emits one inflow point per day', () => {
        const geo = ReserveMath.chartData(daily, 300, 100);
        expect(geo.inflowPoints.split(' ')).toHaveLength(3);
    });

    it('handles empty and all-zero series', () => {
        expect(ReserveMath.chartData([], 300, 100)).toEqual({ bars: [], inflowPoints: '', max: 0 });
        const geo = ReserveMath.chartData([{ day: 'd', outflow_minor: 0, inflow_minor: 0 }], 300, 100);
        expect(geo.max).toBe(0);
        expect(geo.bars[0].h).toBe(0);
    });
});

describe('scaleFor', () => {
    // The map the status endpoint's buckets produce (migrations 031 + 036).
    const scales = { USD: 2, USDC: 7, XLM: 7, USDT0: 7 };

    it('resolves a bucket currency from the status map', () => {
        expect(ReserveMath.scaleFor(scales, 'USD')).toEqual({ scale: 2, known: true });
        expect(ReserveMath.scaleFor(scales, 'USDC')).toEqual({ scale: 7, known: true });
        expect(ReserveMath.scaleFor({ X: 0 }, 'X')).toEqual({ scale: 0, known: true });
    });

    it('never guesses: an unknown currency or an empty map is known:false', () => {
        expect(ReserveMath.scaleFor(scales, 'EURC')).toEqual({ scale: null, known: false });
        expect(ReserveMath.scaleFor({}, 'USD')).toEqual({ scale: null, known: false });
        expect(ReserveMath.scaleFor(null, 'USD').known).toBe(false);
        expect(ReserveMath.scaleFor(undefined, 'USD').known).toBe(false);
        expect(ReserveMath.scaleFor(scales, null).known).toBe(false);
        expect(ReserveMath.scaleFor(scales, undefined).known).toBe(false);
    });

    it('treats a malformed scale as unknown rather than usable', () => {
        expect(ReserveMath.scaleFor({ USD: '2' }, 'USD').known).toBe(false);
        expect(ReserveMath.scaleFor({ USD: -1 }, 'USD').known).toBe(false);
        expect(ReserveMath.scaleFor({ USD: 2.5 }, 'USD').known).toBe(false);
        expect(ReserveMath.scaleFor({ USD: null }, 'USD').known).toBe(false);
        // Inherited Object properties are not bucket entries.
        expect(ReserveMath.scaleFor(scales, 'toString').known).toBe(false);
        expect(ReserveMath.scaleFor(scales, 'hasOwnProperty').known).toBe(false);
    });
});

describe('displayFor / fmtDeltaFor / rawMinor', () => {
    const scales = { USD: 2, USDC: 7 };

    it('renders the USD ledger row that used to show as +0.025', () => {
        // clients-2: a $2,500.00 fiat_confirmed (250000 cents) rendered at the
        // 7-dp fallback scale whenever the ledger landed before status.
        expect(ReserveMath.displayFor(250000, scales, 'USD')).toBe('2,500');
        expect(ReserveMath.fmtDeltaFor(250000, scales, 'USD')).toBe('+2,500');
        expect(ReserveMath.fmtDeltaFor(-250000, scales, 'USD')).toBe('−2,500');
        expect(ReserveMath.displayFor(255000000, scales, 'USDC')).toBe('25.50');
    });

    it('labels raw minor units when the scale is unknown instead of guessing 7', () => {
        expect(ReserveMath.displayFor(250000, {}, 'USD')).toBe('250000 minor units (scale unknown)');
        expect(ReserveMath.fmtDeltaFor(250000, {}, 'USD')).toBe('+250000 minor units (scale unknown)');
        expect(ReserveMath.fmtDeltaFor(-250000, {}, 'USD')).toBe('−250000 minor units (scale unknown)');
        expect(ReserveMath.fmtDeltaFor(0, {}, 'USD')).toBe('0');
        expect(ReserveMath.displayFor(250000, {}, 'USD')).not.toBe('0.025');
        expect(ReserveMath.displayFor(5, scales, null)).toBe('5 minor units (scale unknown)');
    });

    it('rawMinor carries the caller\'s reason verbatim', () => {
        expect(ReserveMath.rawMinor(42, 'summed across currencies'))
            .toBe('42 minor units (summed across currencies)');
    });
});

describe('replenishLegs', () => {
    it('mirrors replenish.rs: caps are denominated in the SPEND asset', () => {
        expect(ReserveMath.replenishLegs('xlm_to_usdc')).toEqual({ spend: 'XLM', recv: 'USDC' });
        expect(ReserveMath.replenishLegs('usdc_to_usd')).toEqual({ spend: 'USDC', recv: 'USD' });
    });

    it('does not mirror the bridge catch-all for an unknown kind', () => {
        expect(ReserveMath.replenishLegs('eurc_to_eur')).toBeNull();
        expect(ReserveMath.replenishLegs('')).toBeNull();
        expect(ReserveMath.replenishLegs(undefined)).toBeNull();
    });
});

describe('cycleArrivalCurrency', () => {
    const fiat = { kind: 'usdc_to_usd', spend_currency: 'USDC', recv_currency: 'USD' };
    const crypto = { kind: 'xlm_to_usdc', spend_currency: 'XLM', recv_currency: 'USDC' };

    it('a refunded cycle got its SPEND asset back (classify_cycle_arrival → Refund)', () => {
        expect(ReserveMath.cycleArrivalCurrency({ ...fiat, state: 'refunded' })).toBe('USDC');
        expect(ReserveMath.cycleArrivalCurrency({ ...crypto, state: 'refunded' })).toBe('XLM');
    });

    it('every other state received the recv asset', () => {
        for (const state of ['completed', 'in_transit', 'sent', 'settled', 'frozen', 'failed', 'planned']) {
            expect(ReserveMath.cycleArrivalCurrency({ ...fiat, state })).toBe('USD');
            expect(ReserveMath.cycleArrivalCurrency({ ...crypto, state })).toBe('USDC');
        }
    });
});

describe('sequenceLoads', () => {
    function deferred() {
        let resolve, reject;
        const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
        return { promise, resolve, reject };
    }
    const flush = () => new Promise((r) => setTimeout(r, 0));

    it('starts dependents only after `first` settles; independents start at once', async () => {
        const calls = [];
        const errors = [];
        const status = deferred();
        const first = () => { calls.push('status'); return status.promise; };
        const ledger = () => { calls.push('ledger'); return Promise.resolve(); };
        const refunds = () => { calls.push('refunds'); return Promise.resolve(); };
        const queues = () => { calls.push('queues'); return Promise.resolve(); };

        const done = ReserveMath.sequenceLoads(first, [ledger, refunds], [queues], (e) => errors.push(e));
        await flush();
        // Status is slow (a Horizon round-trip): the scaled sections wait,
        // the independent ones do not.
        expect(calls).toEqual(['status', 'queues']);

        status.resolve({ buckets: [] });
        await done;
        expect(calls).toEqual(['status', 'queues', 'ledger', 'refunds']);
        expect(errors).toEqual([]);
    });

    it('still runs dependents when `first` rejects, reporting that failure once', async () => {
        const calls = [];
        const errors = [];
        const first = () => Promise.reject(new Error('status boom'));
        const ledger = () => { calls.push('ledger'); return Promise.resolve(); };

        await ReserveMath.sequenceLoads(first, [ledger], [], (e) => errors.push(e.message));
        expect(calls).toEqual(['ledger']);
        expect(errors).toEqual(['status boom']);
    });

    it('reports each failing loader exactly once (sync throws included) and never rejects', async () => {
        const errors = [];
        await ReserveMath.sequenceLoads(
            () => Promise.resolve(),
            [() => Promise.reject(new Error('a')), () => { throw new Error('b'); }],
            [() => Promise.reject(new Error('c'))],
            (e) => errors.push(e.message)
        );
        expect(errors.sort()).toEqual(['a', 'b', 'c']);
    });

    it('resolves only once every loader has settled', async () => {
        const slow = deferred();
        let settled = false;
        const done = ReserveMath.sequenceLoads(() => Promise.resolve(), [], [() => slow.promise], () => {})
            .then(() => { settled = true; });
        await flush();
        expect(settled).toBe(false);
        slow.resolve();
        await done;
        expect(settled).toBe(true);
    });
});
