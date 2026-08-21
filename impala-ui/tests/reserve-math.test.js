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
