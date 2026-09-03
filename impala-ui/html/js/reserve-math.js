/**
 * Pure formatting, validation, and chart-geometry helpers for the
 * conversion-reserve admin page.
 *
 * DOM-free by design (loadable under Node for vitest): reserve.js does the
 * fetching and rendering; everything numeric or geometric lives here, plus
 * the load-ordering rule that keeps money columns from rendering before the
 * scale map they need (sequenceLoads). All money values are integer minor
 * units (USDC/XLM 7 dp, USD cents) exactly as the bridge's
 * /admin/exchange-reserve API returns them — this module never parses
 * user-typed amounts into floats for arithmetic, only for validation bounds
 * mirrored from the server ($20-$200 in whole cents). A currency whose scale
 * is not in the bucket map renders as labelled raw minor units, never at a
 * guessed scale (scaleFor / rawMinor).
 *
 * @module ReserveMath
 */
var ReserveMath = (function () {
    /** Server-mirrored threshold band (USD cents): the $20-$200 requirement. */
    var THRESHOLD_MIN_CENTS = 2000;
    var THRESHOLD_MAX_CENTS = 20000;

    /**
     * Render integer minor units as a decimal string at `scale` places,
     * without floats (BigInt-free: split on the base as strings).
     * @param {number} minor - Integer minor units (may be negative).
     * @param {number} scale - Decimal places of the minor unit.
     * @returns {string} e.g. minorToDecimal(255000000, 7) === "25.5000000"
     */
    function minorToDecimal(minor, scale) {
        var neg = minor < 0;
        var digits = String(Math.abs(minor));
        while (digits.length <= scale) digits = '0' + digits;
        var intPart = digits.slice(0, digits.length - scale) || '0';
        var frac = scale > 0 ? digits.slice(digits.length - scale) : '';
        return (neg ? '-' : '') + intPart + (frac ? '.' + frac : '');
    }

    /**
     * Human display of minor units: thousands separators, trailing zeros
     * trimmed to at most 2 decimals (but full precision kept when the tail
     * is significant).
     * @param {number} minor
     * @param {number} scale
     * @returns {string} e.g. display(2000000000, 7) === "200"
     */
    function display(minor, scale) {
        var s = minorToDecimal(minor, scale);
        var neg = s.charAt(0) === '-';
        if (neg) s = s.slice(1);
        var parts = s.split('.');
        var intPart = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        var frac = (parts[1] || '').replace(/0+$/, '');
        if (frac.length === 1) frac += '0';
        return (neg ? '-' : '') + intPart + (frac ? '.' + frac : '');
    }

    /**
     * USD cents to "$12.34" (negative: "-$12.34").
     * @param {number} cents
     * @returns {string}
     */
    function centsToUsd(cents) {
        var neg = cents < 0;
        var abs = Math.abs(cents);
        var dollars = Math.floor(abs / 100);
        var rem = String(abs % 100);
        if (rem.length < 2) rem = '0' + rem;
        return (neg ? '-$' : '$') +
            String(dollars).replace(/\B(?=(\d{3})+(?!\d))/g, ',') + '.' + rem;
    }

    /**
     * Signed ledger delta for the journal table: "+25.50" / "−3.20" / "0".
     * @param {number} minor
     * @param {number} scale
     * @returns {string}
     */
    function fmtDelta(minor, scale) {
        if (minor === 0) return '0';
        var body = display(Math.abs(minor), scale);
        return (minor > 0 ? '+' : '−') + body;
    }

    /**
     * Resolve a currency's minor-unit scale from the bucket map the status
     * endpoint returns (`currency -> minor_scale`).
     *
     * Never guesses. The ledger, refund, and replenishment endpoints return
     * minor integers without a scale, and the buckets span two scales (USD
     * cents vs 7-dp stablecoins/XLM). Defaulting an unknown currency to 7
     * rendered a $2,500.00 fiat confirmation as "+0.025" whenever the ledger
     * landed before the status call, and a treasurer booked a corrective
     * adjustment against it. `known: false` tells the caller to show raw
     * minor units instead (see rawMinor).
     * @param {Object<string, number>} scales
     * @param {string} currency
     * @returns {{scale: (number|null), known: boolean}}
     */
    function scaleFor(scales, currency) {
        if (scales && typeof currency === 'string' &&
            Object.prototype.hasOwnProperty.call(scales, currency)) {
            var s = scales[currency];
            if (typeof s === 'number' && isFinite(s) && s >= 0 && Math.floor(s) === s) {
                return { scale: s, known: true };
            }
        }
        return { scale: null, known: false };
    }

    /**
     * Raw minor-unit rendering for a value whose scale cannot be resolved:
     * the exact integer the bridge returned plus an explicit reason, so the
     * reader sees "250000 minor units (scale unknown)" rather than a decimal
     * that quietly asserts a scale nobody verified.
     * @param {number} minor
     * @param {string} reason - e.g. 'scale unknown'
     * @returns {string}
     */
    function rawMinor(minor, reason) {
        return String(minor) + ' minor units (' + reason + ')';
    }

    /**
     * Display minor units in `currency`, scaled by the bucket map when the
     * currency is known and as labelled raw minor units otherwise.
     * @param {number} minor
     * @param {Object<string, number>} scales
     * @param {string} currency
     * @returns {string}
     */
    function displayFor(minor, scales, currency) {
        var info = scaleFor(scales, currency);
        return info.known ? display(minor, info.scale) : rawMinor(minor, 'scale unknown');
    }

    /**
     * Signed delta in `currency` (see displayFor for the unknown-scale rule).
     * @param {number} minor
     * @param {Object<string, number>} scales
     * @param {string} currency
     * @returns {string}
     */
    function fmtDeltaFor(minor, scales, currency) {
        var info = scaleFor(scales, currency);
        if (info.known) return fmtDelta(minor, info.scale);
        if (minor === 0) return '0';
        return (minor > 0 ? '+' : '−') + rawMinor(Math.abs(minor), 'scale unknown');
    }

    /**
     * The two legs of a replenishment kind. Mirrors replenish.rs: the policy
     * caps (`max_spend_minor`, `daily_spend_cap_minor`, `min_float_minor`)
     * are all denominated in the SPEND asset. An unknown kind resolves to
     * null so callers fall back to raw minor units rather than a guess —
     * the bridge's own catch-all maps unknown kinds to USDC→USD, but
     * mirroring a catch-all here would be exactly the guessing this module
     * exists to avoid.
     * @param {string} kind
     * @returns {({spend: string, recv: string}|null)}
     */
    function replenishLegs(kind) {
        if (kind === 'xlm_to_usdc') return { spend: 'XLM', recv: 'USDC' };
        if (kind === 'usdc_to_usd') return { spend: 'USDC', recv: 'USD' };
        return null;
    }

    /**
     * Which currency a replenishment cycle's `actual_recv_minor` is in.
     *
     * A refunded cycle's arrival is the SPEND asset coming back (replenish.rs
     * classify_cycle_arrival → Refund books `actual_recv_minor` in
     * spend_currency); every other state received the recv asset. Scaling a
     * refunded XLM→USDC cycle by recv_currency would show XLM at USDC's
     * scale — both 7 dp today, but a refunded USDC→USD cycle holds USDC (7)
     * where recv is USD (2).
     * @param {{state: string, spend_currency: string, recv_currency: string}} cycle
     * @returns {string}
     */
    function cycleArrivalCurrency(cycle) {
        return cycle.state === 'refunded' ? cycle.spend_currency : cycle.recv_currency;
    }

    /**
     * Run page loaders in dependency order. `first` (the status fetch, which
     * carries the bucket scale map) settles before any of `dependents`
     * starts, so the money columns they render never paint against an
     * empty scale map; `independents` start immediately. Dependents run
     * after `first` settles either way — with the scale map absent they
     * render raw minor units, which beats an empty section, and their own
     * requests surface their own errors.
     *
     * Pure orchestration: every loader is a thunk returning a promise, every
     * failure goes to `onError` exactly once, and the returned promise
     * resolves once all loaders have settled (never rejects).
     * @param {function(): Promise} first
     * @param {Array<function(): Promise>} dependents
     * @param {Array<function(): Promise>} independents
     * @param {function(Error)} onError
     * @returns {Promise<void>}
     */
    function sequenceLoads(first, dependents, independents, onError) {
        function run(fn) {
            return new Promise(function (resolve) { resolve(fn()); })
                .then(function () {}, function (err) { onError(err); });
        }
        var chain = run(first).then(function () {
            return Promise.all(dependents.map(run));
        });
        var side = Promise.all(independents.map(run));
        return Promise.all([chain, side]).then(function () {});
    }

    /**
     * Validate an admin-typed threshold in whole dollars against the
     * server's $20-$200 band. Mirrors the bridge's validation — the server
     * remains the source of truth.
     * @param {string} input - e.g. "150" or "150.50"
     * @returns {{ok: boolean, cents: (number|null), error: (string|null)}}
     */
    function validateThresholdDollars(input) {
        var s = String(input == null ? '' : input).trim();
        if (!/^\d+(\.\d{1,2})?$/.test(s)) {
            return { ok: false, cents: null, error: 'Enter a dollar amount like 150 or 150.50' };
        }
        var parts = s.split('.');
        var cents = parseInt(parts[0], 10) * 100 +
            (parts[1] ? parseInt((parts[1] + '0').slice(0, 2), 10) : 0);
        if (cents < THRESHOLD_MIN_CENTS || cents > THRESHOLD_MAX_CENTS) {
            return { ok: false, cents: null, error: 'Threshold must be between $20 and $200' };
        }
        return { ok: true, cents: cents, error: null };
    }

    /**
     * Validate an admin-typed manual-entry amount in display units into
     * integer minor units (no floats: string arithmetic).
     * @param {string} input
     * @param {number} scale
     * @returns {{ok: boolean, minor: (number|null), error: (string|null)}}
     */
    function validateAmount(input, scale) {
        var s = String(input == null ? '' : input).trim();
        var re = scale === 0
            ? /^\d+$/
            : new RegExp('^\\d+(\\.\\d{1,' + scale + '})?$');
        if (!re.test(s)) {
            return { ok: false, minor: null, error: 'Enter a positive amount with at most ' + scale + ' decimal places' };
        }
        var parts = s.split('.');
        var frac = parts[1] || '';
        while (frac.length < scale) frac += '0';
        var minor = parseInt(parts[0] + frac, 10);
        if (!isFinite(minor) || minor > Number.MAX_SAFE_INTEGER) {
            return { ok: false, minor: null, error: 'Amount is too large' };
        }
        if (minor <= 0) {
            return { ok: false, minor: null, error: 'Amount must be positive' };
        }
        return { ok: true, minor: minor, error: null };
    }

    /**
     * Badge class for a days-to-depletion projection.
     * @param {(number|null|undefined)} days
     * @returns {string} 'neutral' (no outflow) | 'ok' | 'pending' | 'error'
     */
    function depletionBadge(days) {
        if (days === null || days === undefined) return 'neutral';
        if (days <= 7) return 'error';
        if (days <= 30) return 'pending';
        return 'ok';
    }

    /**
     * Badge class for a refund obligation's status.
     *
     * `frozen` and `failed` are red because both mean customer money is
     * waiting on a human, not because the request errored.
     * @param {string} status
     * @returns {string} 'ok' | 'error' | 'pending' | 'neutral'
     */
    function refundBadge(status) {
        if (status === 'sent') return 'ok';
        if (status === 'frozen' || status === 'failed') return 'error';
        if (status === 'needs_review') return 'pending';
        return 'neutral';
    }

    /**
     * Badge class for a replenishment cycle's state.
     *
     * `in_transit` is amber rather than green: the provider says it paid,
     * but nobody has confirmed the bank credit, so the money is not yet real.
     * @param {string} state
     * @returns {string} 'ok' | 'error' | 'pending' | 'neutral'
     */
    function cycleBadge(state) {
        if (state === 'completed') return 'ok';
        if (state === 'frozen' || state === 'failed') return 'error';
        if (state === 'in_transit') return 'pending';
        return 'neutral';
    }

    /**
     * Geometry for the utilization chart: outflow bars + an inflow line,
     * scaled into a width x height viewBox. Pure data — reserve.js turns it
     * into SVG markup.
     * @param {Array<{day: string, outflow_minor: number, inflow_minor: number}>} daily
     * @param {number} width
     * @param {number} height
     * @returns {{bars: Array<{x:number,y:number,w:number,h:number,day:string,outflow:number}>,
     *            inflowPoints: string, max: number}}
     */
    function chartData(daily, width, height) {
        var n = daily.length;
        if (!n) return { bars: [], inflowPoints: '', max: 0 };
        var max = 0;
        daily.forEach(function (d) {
            if (d.outflow_minor > max) max = d.outflow_minor;
            if (d.inflow_minor > max) max = d.inflow_minor;
        });
        var denom = max > 0 ? max : 1;
        var step = width / n;
        var barW = Math.max(1, Math.floor(step * 0.7));
        var bars = daily.map(function (d, i) {
            var h = Math.round((d.outflow_minor / denom) * (height - 2));
            return {
                x: Math.round(i * step + (step - barW) / 2),
                y: height - h,
                w: barW,
                h: h,
                day: d.day,
                outflow: d.outflow_minor
            };
        });
        var inflowPoints = daily.map(function (d, i) {
            var y = height - Math.round((d.inflow_minor / denom) * (height - 2));
            return Math.round(i * step + step / 2) + ',' + y;
        }).join(' ');
        return { bars: bars, inflowPoints: inflowPoints, max: max };
    }

    return {
        THRESHOLD_MIN_CENTS: THRESHOLD_MIN_CENTS,
        THRESHOLD_MAX_CENTS: THRESHOLD_MAX_CENTS,
        minorToDecimal: minorToDecimal,
        display: display,
        centsToUsd: centsToUsd,
        fmtDelta: fmtDelta,
        scaleFor: scaleFor,
        rawMinor: rawMinor,
        displayFor: displayFor,
        fmtDeltaFor: fmtDeltaFor,
        replenishLegs: replenishLegs,
        cycleArrivalCurrency: cycleArrivalCurrency,
        sequenceLoads: sequenceLoads,
        validateThresholdDollars: validateThresholdDollars,
        validateAmount: validateAmount,
        depletionBadge: depletionBadge,
        refundBadge: refundBadge,
        cycleBadge: cycleBadge,
        chartData: chartData
    };
})();
