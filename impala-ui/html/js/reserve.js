/**
 * Conversion-reserve admin console.
 *
 * Renders the bridge's /admin/exchange-reserve API: bucket balances with
 * on-chain drift, per-provider routing policies ($20-$200 thresholds), a
 * hand-rolled SVG utilization chart with depletion forecasting, the admin
 * work queues (fiat disbursements, frozen payouts), the reserve ledger, and
 * the stray-inflow queue. All numeric/geometry logic lives in the DOM-free
 * ReserveMath module; every dynamic value rendered here is escaped.
 *
 * Money columns depend on the per-bucket minor scales that ONLY the status
 * call returns (the ledger, refund, and replenishment endpoints hand back
 * bare minor integers). Two rules keep a USD row from ever painting at a
 * 7-dp scale: those sections load only after status has settled
 * (ReserveMath.sequenceLoads), and a currency whose scale is still unknown
 * renders as labelled raw minor units, never at a guessed scale
 * (ReserveMath.displayFor). Each section keeps its last payload so a status
 * refresh re-renders it against the current scale map.
 *
 * @module ReservePage
 */
(function () {
    'use strict';

    Router.init();
    if (!Router.requirePermission('view_reserve', 'Reserve')) return;

    // One flag, applied at every action-injection point below: viewers
    // without it (the auditor) get the same live page, read-only. The bridge
    // enforces the same boundary server-side regardless — which is also why
    // the injection points carry no unit tests (they live in DOM rendering,
    // outside the DOM-free test style): a missed gate here shows a button
    // whose request 403s, never an unauthorized mutation.
    var canManage = Roles.currentUserHasPermission('manage_reserve');

    var escapeHtml = EscapeHtml.escape;

    /**
     * Latest payloads. Status/forecast re-render together; ledger, refunds
     * and replenishment are cached so a later status load (new scale map)
     * can re-render them without a refetch.
     */
    var state = {
        status: null,
        forecast: null,
        scales: {},          // currency -> minor_scale, from status buckets only
        ledger: null,
        refunds: null,
        replenishment: null,
        ledgerPage: 1,
        unmatchedPage: 1
    };
    var SCALED_SECTIONS = ['reserve-ledger', 'reserve-refunds', 'reserve-replenishment'];

    /** Minor units in `currency`, scaled by the status bucket map or labelled raw. */
    function money(minor, currency) {
        return escapeHtml(ReserveMath.displayFor(minor, state.scales, currency));
    }

    /** Signed delta in `currency`, same scale rule as money(). */
    function delta(minor, currency) {
        return escapeHtml(ReserveMath.fmtDeltaFor(minor, state.scales, currency));
    }

    function showLoading(ids) {
        ids.forEach(function (id) {
            document.getElementById(id).innerHTML = '<p class="text-muted">Loading&hellip;</p>';
        });
    }

    /** Re-render every cached scale-dependent section against state.scales. */
    function rerenderScaled() {
        if (state.ledger) renderLedger();
        if (state.refunds) renderRefunds();
        if (state.replenishment) renderReplenishment();
    }
    var PER_PAGE = 10;
    // Mirrors chk_conversion_reserve_entry_kind (migrations 031 + 032). A
    // kind missing here silently disappears from the ledger filter.
    var ENTRY_KINDS = ['hold', 'hold_release', 'deposit', 'unmatched_deposit',
        'payout_attempt', 'fulfillment', 'disbursement', 'topup', 'withdrawal',
        'adjustment', 'held_adjustment',
        'quote_hold', 'quote_release', 'quote_consume',
        'replenish_hold', 'replenish_attempt', 'replenish_sent',
        'replenish_credit', 'replenish_refund', 'replenish_release',
        'offramp_hold', 'offramp_attempt', 'offramp_sent', 'offramp_refund',
        'fiat_in_transit', 'fiat_confirmed', 'fiat_written_off',
        'refund_intent', 'refund_sent', 'refund_reversal'];
    var ADMIN_KINDS = ['topup', 'withdrawal', 'adjustment', 'held_adjustment'];

    /* ---- status: buckets + policies -------------------------------------- */

    function loadStatus() {
        return API.get('/admin/exchange-reserve').then(function (res) {
            state.status = res;
            (res.buckets || []).forEach(function (b) {
                state.scales[b.currency] = b.minor_scale;
            });
            document.getElementById('reserve-unconfigured').hidden = !!res.configured;
            renderBuckets();
            renderPolicies();
            // The scale map may have changed (first load, or a bucket added):
            // anything already on screen must reflect it.
            rerenderScaled();
        });
    }

    function forecastFor(currency) {
        var list = (state.forecast && state.forecast.currencies) || [];
        for (var i = 0; i < list.length; i++) {
            if (list[i].currency === currency) return list[i];
        }
        return null;
    }

    function renderBuckets() {
        var res = state.status;
        if (!res) return;
        var html = '<div class="grid-x grid-margin-x">';
        (res.buckets || []).forEach(function (b) {
            var f = forecastFor(b.currency);
            var days = f ? f.projected_days_to_depletion : null;
            var badge = ReserveMath.depletionBadge(days === undefined ? null : days);
            var daysLabel = (days === null || days === undefined) ? 'no outflow' : days + 'd left';
            var low = b.low_water_minor > 0 && b.available_minor < b.low_water_minor;
            html += '<div class="cell medium-4"><div class="stat-card">' +
                '<div style="display:flex;justify-content:space-between;align-items:baseline;">' +
                '<strong>' + escapeHtml(b.currency) + '</strong>' +
                '<span class="badge ' + badge + '">' + escapeHtml(daysLabel) + '</span></div>' +
                '<div class="stat-value">' + escapeHtml(ReserveMath.display(b.available_minor, b.minor_scale)) + '</div>' +
                '<div class="text-muted">available' + (low ? ' <span class="badge error">below low water</span>' : '') + '</div>' +
                '<dl class="detail-grid">' +
                '<dt>Held</dt><dd>' + escapeHtml(ReserveMath.display(b.held_minor, b.minor_scale)) + '</dd>' +
                '<dt>Low water</dt><dd>' + escapeHtml(ReserveMath.display(b.low_water_minor, b.minor_scale)) + '</dd>' +
                '<dt>On-chain</dt><dd>' + (b.onchain_balance ? escapeHtml(b.onchain_balance) : '<span class="text-muted">unavailable</span>') + '</dd>' +
                // Stablecoin buckets carry their pinned CODE:ISSUER; a
                // configured asset the account cannot hold yet is the one
                // state an admin must act on, so it gets a badge + button.
                (b.asset ? '<dt>Asset</dt><dd class="mono">' + escapeHtml(b.asset) +
                    (b.trustline === false ? ' <span class="badge error">no trustline</span>' : '') + '</dd>' : '') +
                '</dl>' +
                (canManage
                    ? '<button type="button" class="button tiny secondary bucket-edit" data-currency="' + escapeHtml(b.currency) + '" data-low="' + b.low_water_minor + '" data-scale="' + b.minor_scale + '">Set low water</button>'
                    : '') +
                (canManage && b.asset && b.trustline === false
                    ? ' <button type="button" class="button tiny trustline-add" data-currency="' + escapeHtml(b.currency) + '">Add trustline</button>'
                    : '') +
                '</div></div>';
        });
        html += '</div>';
        if (res.stellar_address) {
            html += '<p class="text-muted">Pay-in address: <span class="mono">' + escapeHtml(res.stellar_address) + '</span></p>';
        }
        var container = document.getElementById('reserve-buckets');
        container.innerHTML = html;
        container.querySelectorAll('.bucket-edit').forEach(function (btn) {
            btn.addEventListener('click', function () {
                openBucketModal(btn.getAttribute('data-currency'),
                    parseInt(btn.getAttribute('data-low'), 10),
                    parseInt(btn.getAttribute('data-scale'), 10));
            });
        });
        container.querySelectorAll('.trustline-add').forEach(function (btn) {
            btn.addEventListener('click', function () {
                openTrustlineModal(btn.getAttribute('data-currency'));
            });
        });
    }

    function renderPolicies() {
        var res = state.status;
        if (!res) return;
        var html = '<div class="table-wrap"><table><thead><tr>' +
            '<th>Provider</th><th>Enabled</th><th>Threshold</th><th>Updated</th><th></th>' +
            '</tr></thead><tbody>';
        (res.policies || []).forEach(function (p) {
            var enabledBadge = p.supported
                ? (p.enabled ? '<span class="badge ok">enabled</span>' : '<span class="badge neutral">disabled</span>')
                : '<span class="badge neutral">not supported</span>';
            html += '<tr><td class="mono">' + escapeHtml(p.provider) + '</td>' +
                '<td>' + enabledBadge + '</td>' +
                '<td>' + escapeHtml(ReserveMath.centsToUsd(p.threshold_usd_cents)) + '</td>' +
                '<td>' + escapeHtml(p.updated_at || '') + '</td>' +
                '<td>' + (p.supported && canManage
                    ? '<button type="button" class="button tiny secondary policy-edit" data-provider="' + escapeHtml(p.provider) + '" data-enabled="' + p.enabled + '" data-threshold="' + p.threshold_usd_cents + '">Edit</button>'
                    : '') + '</td></tr>';
        });
        html += '</tbody></table></div>';
        var container = document.getElementById('reserve-policies');
        container.innerHTML = html;
        container.querySelectorAll('.policy-edit').forEach(function (btn) {
            btn.addEventListener('click', function () {
                openPolicyModal(btn.getAttribute('data-provider'),
                    btn.getAttribute('data-enabled') === 'true',
                    parseInt(btn.getAttribute('data-threshold'), 10));
            });
        });
    }

    function openPolicyModal(provider, enabled, thresholdCents) {
        var body =
            '<p class="text-muted">Orders at or under the threshold divert to the reserve; the bridge enforces the $20&ndash;$200 band.</p>' +
            '<label><input type="checkbox" id="policy-enabled"' + (enabled ? ' checked' : '') + '> Enabled</label>' +
            '<label>Threshold (USD)<input type="text" id="policy-threshold" value="' + escapeHtml(ReserveMath.centsToUsd(thresholdCents).replace(/[$,]/g, '')) + '"></label>' +
            '<p class="form-error" id="policy-error" hidden></p>';
        Modal.open({
            title: 'Reserve policy — ' + provider,
            bodyHtml: body,
            confirmLabel: 'Save policy',
            onConfirm: function (dialog, helpers) {
                var check = ReserveMath.validateThresholdDollars(dialog.querySelector('#policy-threshold').value);
                var errEl = dialog.querySelector('#policy-error');
                if (!check.ok) {
                    errEl.textContent = check.error;
                    errEl.hidden = false;
                    return;
                }
                API.setButtonLoading(helpers.button, true);
                API.put('/admin/exchange-reserve/policies/' + encodeURIComponent(provider), {
                    enabled: dialog.querySelector('#policy-enabled').checked,
                    threshold_usd_cents: check.cents
                }).then(function (res) {
                    Router.showToast((res && res.message) || 'Policy updated', 'success');
                    helpers.close();
                    loadStatus();
                }).catch(function (err) {
                    Router.showToast('Error: ' + err.message, 'alert');
                }).then(function () { API.setButtonLoading(helpers.button, false); });
            }
        });
    }

    function openTrustlineModal(currency) {
        var body =
            '<p>The bridge signs a <code>ChangeTrust</code> from the reserve seed so the reserve ' +
            'account can hold <strong>' + escapeHtml(currency) + '</strong>. This moves no money; ' +
            'it reserves ~0.5 XLM of base reserve on the account. Repeating it is a no-op.</p>';
        Modal.open({
            title: 'Add trustline — ' + currency,
            bodyHtml: body,
            confirmLabel: 'Add trustline',
            onConfirm: function (dialog, helpers) {
                API.setButtonLoading(helpers.button, true);
                API.post('/admin/exchange-reserve/trustlines', { currency: currency })
                    .then(function (res) {
                        if (res && res.success === false) {
                            Router.showToast(res.message || 'Trustline failed', 'alert');
                            return;
                        }
                        Router.showToast('Trustline in place (tx ' + String(res.stellar_tx_hash || '').slice(0, 8) + '\u2026)', 'success');
                        helpers.close();
                        loadStatus();
                    })
                    .catch(function (err) { Router.showToast('Error: ' + err.message, 'alert'); })
                    .then(function () { API.setButtonLoading(helpers.button, false); });
            }
        });
    }

    function openBucketModal(currency, lowWaterMinor, scale) {
        var body =
            '<label>Low-water mark (' + escapeHtml(currency) + ')' +
            '<input type="text" id="bucket-low" value="' + escapeHtml(ReserveMath.minorToDecimal(lowWaterMinor, scale)) + '"></label>' +
            '<p class="text-muted">A <code>reserve.low_water</code> event fires when available drops below this. 0 disables the alert.</p>' +
            '<p class="form-error" id="bucket-error" hidden></p>';
        Modal.open({
            title: 'Low water — ' + currency,
            bodyHtml: body,
            confirmLabel: 'Save',
            onConfirm: function (dialog, helpers) {
                var raw = dialog.querySelector('#bucket-low').value.trim();
                var minor = 0;
                if (raw !== '0' && raw !== '') {
                    var check = ReserveMath.validateAmount(raw, scale);
                    var errEl = dialog.querySelector('#bucket-error');
                    if (!check.ok) {
                        errEl.textContent = check.error;
                        errEl.hidden = false;
                        return;
                    }
                    minor = check.minor;
                }
                API.setButtonLoading(helpers.button, true);
                API.put('/admin/exchange-reserve/buckets/' + encodeURIComponent(currency), {
                    low_water_minor: minor
                }).then(function (res) {
                    Router.showToast((res && res.message) || 'Bucket updated', 'success');
                    helpers.close();
                    loadStatus();
                }).catch(function (err) {
                    Router.showToast('Error: ' + err.message, 'alert');
                }).then(function () { API.setButtonLoading(helpers.button, false); });
            }
        });
    }

    /* ---- forecast --------------------------------------------------------- */

    function loadForecast() {
        var windowDays = document.getElementById('forecast-window').value;
        return API.get('/admin/exchange-reserve/forecast?window_days=' + windowDays +
            '&target_days=30').then(function (res) {
            state.forecast = res;
            renderForecast();
            renderBuckets(); // depletion badges depend on the forecast
        });
    }

    function chartSvg(f) {
        var W = 640, H = 120;
        var geo = ReserveMath.chartData(f.daily || [], W, H);
        if (!geo.bars.length || geo.max === 0) {
            return '<p class="text-muted">No flow in this window.</p>';
        }
        var svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" ' +
            'aria-label="Daily reserve flows for ' + escapeHtml(f.currency) + '" ' +
            'style="width:100%;height:auto;display:block;">';
        geo.bars.forEach(function (b) {
            svg += '<rect x="' + b.x + '" y="' + b.y + '" width="' + b.w + '" height="' + b.h + '"' +
                ' fill="var(--primary)" opacity="0.75">' +
                '<title>' + escapeHtml(b.day) + ': -' + escapeHtml(ReserveMath.display(b.outflow, f.minor_scale)) + '</title></rect>';
        });
        svg += '<polyline points="' + geo.inflowPoints + '" fill="none" ' +
            'stroke="var(--success)" stroke-width="1.5" opacity="0.9"/>';
        svg += '</svg>';
        return svg;
    }

    function renderForecast() {
        var res = state.forecast;
        if (!res) return;
        var html = '';
        (res.currencies || []).forEach(function (f) {
            var hasFlow = f.avg_daily_outflow_minor > 0 || f.ewma_daily_outflow_minor > 0 ||
                (f.daily || []).some(function (d) { return d.outflow_minor > 0 || d.inflow_minor > 0; });
            if (!hasFlow && f.available_minor === 0) return; // untouched bucket
            var trendLabel = f.trend_minor_per_day > 0 ? 'rising'
                : (f.trend_minor_per_day < 0 ? 'falling' : 'flat');
            html += '<div style="margin-bottom:1.25rem;">' +
                '<div style="display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:0.5rem;">' +
                '<strong>' + escapeHtml(f.currency) + '</strong>' +
                '<span class="text-muted">outflow bars / <span style="color:var(--success);">inflow line</span></span>' +
                '</div>' +
                chartSvg(f) +
                '<dl class="detail-grid" style="margin-top:0.5rem;">' +
                '<dt>Avg daily outflow</dt><dd>' + escapeHtml(ReserveMath.display(f.avg_daily_outflow_minor, f.minor_scale)) + '</dd>' +
                '<dt>EWMA outflow</dt><dd>' + escapeHtml(ReserveMath.display(f.ewma_daily_outflow_minor, f.minor_scale)) + '</dd>' +
                '<dt>Trend</dt><dd>' + escapeHtml(trendLabel) + ' (' + escapeHtml(ReserveMath.fmtDelta(f.trend_minor_per_day, f.minor_scale)) + '/day)</dd>' +
                '<dt>Depletion</dt><dd>' + (f.projected_depletion_date
                    ? escapeHtml(f.projected_depletion_date) + ' (' + f.projected_days_to_depletion + ' days)'
                    : '<span class="text-muted">no projected depletion</span>') + '</dd>' +
                '<dt>Suggested top-up (30d)</dt><dd>' + escapeHtml(ReserveMath.display(f.suggested_topup_minor, f.minor_scale)) + '</dd>' +
                '</dl></div>';
        });
        var util = res.provider_utilization || [];
        if (util.length) {
            html += '<h6>Diverted volume by provider (' + res.window_days + 'd)</h6>' +
                '<div class="table-wrap"><table><thead><tr><th>Provider</th><th>Bucket</th><th>Orders</th><th>Held volume</th></tr></thead><tbody>';
            util.forEach(function (u) {
                // One row per (provider, bucket): the bridge never sums a
                // USD-cents hold with a 7-dp stablecoin hold. Scale by the
                // bucket map; a bucket whose scale is unknown stays raw.
                var sc = ReserveMath.scaleFor(state.scales, u.currency);
                var volume = sc.known
                    ? ReserveMath.display(u.volume_minor, sc.scale) + ' ' + escapeHtml(u.currency || '')
                    : ReserveMath.rawMinor(u.volume_minor, 'scale unknown');
                html += '<tr><td class="mono">' + escapeHtml(u.provider) + '</td>' +
                    '<td>' + escapeHtml(u.currency || '') + '</td>' +
                    '<td>' + u.orders + '</td>' +
                    '<td>' + escapeHtml(volume) + '</td></tr>';
            });
            html += '</tbody></table></div>';
        }
        document.getElementById('reserve-forecast').innerHTML =
            html || '<p class="text-muted">No reserve activity yet.</p>';
    }

    /* ---- work queues ------------------------------------------------------ */

    function loadQueues() {
        return Promise.all([
            API.get('/exchange/orders?provider=reserve&status=processing&per_page=50'),
            API.get('/exchange/orders?provider=reserve&status=on_hold&per_page=50')
        ]).then(function (results) {
            var disbursements = (results[0].data || []).filter(function (o) {
                return o.provider_status === 'awaiting_disbursement';
            });
            var frozen = results[1].data || [];
            renderQueues(disbursements, frozen);
        });
    }

    function orderRow(o, action) {
        return '<tr><td class="mono">' + escapeHtml(o.order_id) + '</td>' +
            '<td class="mono">' + escapeHtml(o.payala_account_id) + '</td>' +
            '<td>' + escapeHtml(o.amount_from) + ' ' + escapeHtml(o.from_currency) +
            ' &rarr; ' + escapeHtml(o.amount_to || '?') + ' ' + escapeHtml(o.to_currency) + '</td>' +
            '<td>' + escapeHtml(o.last_error || o.provider_status || '') + '</td>' +
            '<td>' + action + '</td></tr>';
    }

    function renderQueues(disbursements, frozen) {
        var html = '';
        if (!disbursements.length && !frozen.length) {
            html = '<p class="text-muted">No disbursements pending and no frozen payouts.</p>';
        }
        if (disbursements.length) {
            html += '<h6>Fiat disbursements pending (' + disbursements.length + ')</h6>' +
                '<div class="table-wrap"><table><thead><tr><th>Order</th><th>Account</th><th>Conversion</th><th>State</th><th></th></tr></thead><tbody>';
            disbursements.forEach(function (o) {
                html += orderRow(o, canManage
                    ? '<button type="button" class="button tiny disburse-btn" data-id="' + escapeHtml(o.order_id) + '" data-amount="' + escapeHtml(o.amount_to || '') + '">Disburse</button>'
                    : '');
            });
            html += '</tbody></table></div>';
        }
        if (frozen.length) {
            html += '<h6>Frozen payouts (' + frozen.length + ')</h6>' +
                '<div class="table-wrap"><table><thead><tr><th>Order</th><th>Account</th><th>Conversion</th><th>Reason</th><th></th></tr></thead><tbody>';
            frozen.forEach(function (o) {
                html += orderRow(o, canManage
                    ? '<button type="button" class="button tiny alert resolve-btn" data-id="' + escapeHtml(o.order_id) + '">Resolve</button>'
                    : '');
            });
            html += '</tbody></table></div>';
        }
        var container = document.getElementById('reserve-queues');
        container.innerHTML = html;
        container.querySelectorAll('.disburse-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                openDisburseModal(btn.getAttribute('data-id'), btn.getAttribute('data-amount'));
            });
        });
        container.querySelectorAll('.resolve-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                openResolveModal(btn.getAttribute('data-id'));
            });
        });
    }

    function openDisburseModal(orderId, estAmount) {
        var body =
            '<p class="text-muted">Record the fiat payment made from the USD float. Beneficiary details are in the order&rsquo;s server-side payload (see runbook).</p>' +
            '<label>Amount paid (USD)<input type="text" id="disburse-amount" value="' + escapeHtml(estAmount) + '"></label>' +
            '<label>External reference<input type="text" id="disburse-ref" placeholder="Bank / OwlPay reference"></label>' +
            '<label>Note<textarea id="disburse-note" rows="2"></textarea></label>' +
            '<p class="form-error" id="disburse-error" hidden></p>';
        Modal.open({
            title: 'Record disbursement',
            bodyHtml: body,
            confirmLabel: 'Record & complete',
            onConfirm: function (dialog, helpers) {
                var check = ReserveMath.validateAmount(dialog.querySelector('#disburse-amount').value, 2);
                var errEl = dialog.querySelector('#disburse-error');
                if (!check.ok) {
                    errEl.textContent = check.error;
                    errEl.hidden = false;
                    return;
                }
                API.setButtonLoading(helpers.button, true);
                API.post('/admin/exchange-reserve/orders/' + encodeURIComponent(orderId) + '/disburse', {
                    amount_usd_cents: check.minor,
                    external_ref: dialog.querySelector('#disburse-ref').value.trim() || undefined,
                    note: dialog.querySelector('#disburse-note').value.trim() || undefined
                }).then(function (res) {
                    Router.showToast((res && res.message) || 'Disbursement recorded', 'success');
                    helpers.close();
                    refreshAll();
                }).catch(function (err) {
                    Router.showToast('Error: ' + err.message, 'alert');
                }).then(function () { API.setButtonLoading(helpers.button, false); });
            }
        });
    }

    function openResolveModal(orderId) {
        var body =
            '<p class="text-muted"><strong>Complete</strong> records a payout that landed on-chain (found by memo, or paste the hash). <strong>Fail</strong> releases the hold &mdash; the bridge refuses it while a submitted payment could still land, or when it finds one on-chain.</p>' +
            '<label>Action<select id="resolve-action">' +
            '<option value="complete">complete — payout landed</option>' +
            '<option value="fail">fail — release the hold</option>' +
            '</select></label>' +
            '<label>Stellar tx hash (optional)<input type="text" id="resolve-hash" class="mono" placeholder="auto-detected by memo when omitted"></label>' +
            '<label>Note<textarea id="resolve-note" rows="2"></textarea></label>';
        Modal.open({
            title: 'Resolve frozen payout',
            bodyHtml: body,
            confirmLabel: 'Resolve',
            onConfirm: function (dialog, helpers) {
                API.setButtonLoading(helpers.button, true);
                API.post('/admin/exchange-reserve/orders/' + encodeURIComponent(orderId) + '/resolve', {
                    action: dialog.querySelector('#resolve-action').value,
                    stellar_tx_hash: dialog.querySelector('#resolve-hash').value.trim() || undefined,
                    note: dialog.querySelector('#resolve-note').value.trim() || undefined
                }).then(function (res) {
                    Router.showToast((res && res.message) || 'Order resolved', 'success');
                    helpers.close();
                    refreshAll();
                }).catch(function (err) {
                    Router.showToast('Error: ' + err.message, 'alert');
                }).then(function () { API.setButtonLoading(helpers.button, false); });
            }
        });
    }

    /* ---- ledger ----------------------------------------------------------- */

    function loadLedger() {
        var kind = document.getElementById('ledger-kind').value;
        var qs = 'page=' + state.ledgerPage + '&per_page=' + PER_PAGE +
            (kind ? '&kind=' + encodeURIComponent(kind) : '');
        return API.get('/admin/exchange-reserve/entries?' + qs).then(function (res) {
            state.ledger = res;
            renderLedger();
        });
    }

    function renderLedger() {
        var res = state.ledger;
        var rows = res.data || [];
        var html = '<div class="table-wrap"><table><thead><tr>' +
            '<th>When</th><th>Kind</th><th>Currency</th><th>&Delta; available</th><th>&Delta; held</th><th>After (avail/held)</th><th>Order</th><th>By</th><th>Note</th>' +
            '</tr></thead><tbody>';
        if (!rows.length) {
            html += '<tr><td colspan="9" class="text-muted">No entries.</td></tr>';
        }
        rows.forEach(function (e) {
            html += '<tr><td>' + escapeHtml(e.created_at) + '</td>' +
                '<td><span class="badge neutral">' + escapeHtml(e.kind) + '</span></td>' +
                '<td>' + escapeHtml(e.currency) + '</td>' +
                '<td>' + delta(e.delta, e.currency) + '</td>' +
                '<td>' + delta(e.held_delta, e.currency) + '</td>' +
                '<td>' + money(e.balance_after, e.currency) + ' / ' +
                money(e.held_after, e.currency) + '</td>' +
                '<td class="mono">' + escapeHtml(e.order_id || '') + '</td>' +
                '<td class="mono">' + escapeHtml(e.admin_account_id || '') + '</td>' +
                '<td>' + escapeHtml(e.note || '') + '</td></tr>';
        });
        html += '</tbody></table></div>';
        document.getElementById('reserve-ledger').innerHTML = html;

        Paginate.renderControls({
            page: res.page,
            totalPages: Math.max(1, Math.ceil(res.total / res.per_page)),
            totalItems: res.total
        }, 'ledger-pagination', function (page) {
            state.ledgerPage = page;
            loadLedger();
        });
    }

    function openEntryModal() {
        // Currencies come from the status bucket map, so every option has a
        // known scale; without that map an amount cannot be converted to
        // minor units, so refuse rather than guess.
        var currencies = Object.keys(state.scales).filter(function (c) {
            return ReserveMath.scaleFor(state.scales, c).known;
        });
        if (!currencies.length) {
            Router.showToast('Bucket scales have not loaded yet; refresh and try again', 'alert');
            return;
        }
        var kindOpts = ADMIN_KINDS.map(function (k) {
            return '<option value="' + k + '">' + k + '</option>';
        }).join('');
        var currencyOpts = currencies.map(function (c) {
            return '<option value="' + escapeHtml(c) + '">' + escapeHtml(c) + '</option>';
        }).join('');
        var body =
            '<p class="text-muted">The ledger tracks real value: record a topup only after the matching on-chain or bank funding happened. Withdrawals that would overdraw are refused.</p>' +
            '<label>Kind<select id="entry-kind-input">' + kindOpts + '</select></label>' +
            '<label>Currency<select id="entry-currency">' + currencyOpts + '</select></label>' +
            '<label>Amount<input type="text" id="entry-amount" placeholder="25.50"></label>' +
            '<label><input type="checkbox" id="entry-negative"> Negative (adjustments only)</label>' +
            '<label>Note<textarea id="entry-note" rows="2" placeholder="Why (funding tx hash, ticket, ...)"></textarea></label>' +
            '<p class="form-error" id="entry-error" hidden></p>';
        Modal.open({
            title: 'Record ledger entry',
            bodyHtml: body,
            confirmLabel: 'Record',
            onConfirm: function (dialog, helpers) {
                var currency = dialog.querySelector('#entry-currency').value;
                var kind = dialog.querySelector('#entry-kind-input').value;
                var errEl = dialog.querySelector('#entry-error');
                var scaleInfo = ReserveMath.scaleFor(state.scales, currency);
                if (!scaleInfo.known) {
                    errEl.textContent = 'Scale for ' + currency + ' is unknown; refresh and try again';
                    errEl.hidden = false;
                    return;
                }
                var check = ReserveMath.validateAmount(dialog.querySelector('#entry-amount').value, scaleInfo.scale);
                if (!check.ok) {
                    errEl.textContent = check.error;
                    errEl.hidden = false;
                    return;
                }
                var minor = check.minor;
                var negative = dialog.querySelector('#entry-negative').checked;
                if (negative && kind !== 'adjustment' && kind !== 'held_adjustment') {
                    errEl.textContent = 'Only adjustments may be negative (use withdrawal to remove funds)';
                    errEl.hidden = false;
                    return;
                }
                if (negative) minor = -minor;
                API.setButtonLoading(helpers.button, true);
                API.post('/admin/exchange-reserve/entries', {
                    currency: currency,
                    kind: kind,
                    amount_minor: minor,
                    note: dialog.querySelector('#entry-note').value.trim() || undefined
                }).then(function (res) {
                    Router.showToast((res && res.message) || 'Entry recorded', 'success');
                    helpers.close();
                    refreshAll();
                }).catch(function (err) {
                    Router.showToast('Error: ' + err.message, 'alert');
                }).then(function () { API.setButtonLoading(helpers.button, false); });
            }
        });
    }

    /* ---- unmatched -------------------------------------------------------- */

    function loadUnmatched() {
        var qs = 'page=' + state.unmatchedPage + '&per_page=' + PER_PAGE;
        return API.get('/admin/exchange-reserve/unmatched?' + qs).then(function (res) {
            var rows = res.data || [];
            var html = '<div class="table-wrap"><table><thead><tr>' +
                '<th>Seen</th><th>Reason</th><th>Amount</th><th>Asset</th><th>Sender</th>' +
                '<th>Disposition</th><th>Memo</th><th>Tx</th>' +
                '</tr></thead><tbody>';
            if (!rows.length) {
                html += '<tr><td colspan="8" class="text-muted">No unmatched deposits.</td></tr>';
            }
            rows.forEach(function (u) {
                html += '<tr><td>' + escapeHtml(u.seen_at) + '</td>' +
                    '<td><span class="badge pending">' + escapeHtml(u.reason) + '</span></td>' +
                    '<td>' + escapeHtml(u.amount) + '</td>' +
                    '<td class="mono">' + escapeHtml(u.asset_code || 'XLM') + '</td>' +
                    '<td class="mono">' + escapeHtml(u.sender_address || (u.sender_muxed ? 'muxed' : '')) + '</td>' +
                    '<td>' + (u.refund_id
                        ? '<span class="badge ok">refund queued</span>'
                        : escapeHtml(u.refund_skip_reason || '')) + '</td>' +
                    '<td class="mono">' + escapeHtml(u.memo || '') + '</td>' +
                    '<td class="mono">' + escapeHtml(u.tx_hash) + '</td></tr>';
            });
            html += '</tbody></table></div>';
            document.getElementById('reserve-unmatched').innerHTML = html;
            Paginate.renderControls({
                page: res.page,
                totalPages: Math.max(1, Math.ceil(res.total / res.per_page)),
                totalItems: res.total
            }, 'unmatched-pagination', function (page) {
                state.unmatchedPage = page;
                loadUnmatched();
            });
        });
    }

    /* ---- refunds ----------------------------------------------------------- */

    function loadRefunds() {
        return API.get('/admin/exchange-reserve/refunds?page=1&per_page=' + PER_PAGE)
            .then(function (res) {
                state.refunds = res;
                renderRefunds();
            });
    }

    function renderRefunds() {
        var rows = state.refunds.data || [];
        var html = '<div class="table-wrap"><table><thead><tr>' +
            '<th>When</th><th>Status</th><th>Reason</th><th>Amount</th>' +
            '<th>Destination</th><th>Detail</th><th></th>' +
            '</tr></thead><tbody>';
        if (!rows.length) {
            html += '<tr><td colspan="7" class="text-muted">No refunds.</td></tr>';
        }
        rows.forEach(function (r) {
            html += '<tr><td>' + escapeHtml(r.created_at) + '</td>' +
                '<td><span class="badge ' + ReserveMath.refundBadge(r.status) + '">' +
                escapeHtml(r.status) + '</span></td>' +
                '<td>' + escapeHtml(r.reason) + '</td>' +
                '<td>' + money(r.refund_minor, r.currency) + ' ' +
                escapeHtml(r.currency) + '</td>' +
                '<td class="mono">' + escapeHtml(r.destination) + '</td>' +
                '<td>' + escapeHtml(r.last_error || r.skip_reason || '') + '</td>' +
                '<td>' + refundActions(r) + '</td></tr>';
        });
        html += '</tbody></table></div>';
        var container = document.getElementById('reserve-refunds');
        container.innerHTML = html;
        container.querySelectorAll('.refund-action').forEach(function (btn) {
            btn.addEventListener('click', function () {
                openRefundModal(btn.getAttribute('data-id'),
                    btn.getAttribute('data-action'));
            });
        });
    }

    function refundActions(r) {
        if (!canManage) return '';
        var btn = function (action, label, cls) {
            return '<button type="button" class="button tiny ' + cls +
                ' refund-action" data-id="' + escapeHtml(r.refund_id) +
                '" data-action="' + action + '">' + label + '</button> ';
        };
        if (r.status === 'needs_review') {
            return btn('approve', 'Approve', '') + btn('cancel', 'Cancel', 'secondary');
        }
        if (r.status === 'queued') return btn('cancel', 'Cancel', 'secondary');
        if (r.status === 'frozen') {
            return btn('sent', 'Mark sent', '') + btn('reverse', 'Reverse', 'alert');
        }
        return '';
    }

    function openRefundModal(refundId, action) {
        var needsHash = action === 'sent';
        var warn = action === 'reverse'
            ? '<p class="text-muted">The bridge refuses this until 600s after the claim and only after verifying on-chain that no matching refund exists — reversing one that landed would credit money that left the chain.</p>'
            : '';
        var body = warn +
            (needsHash
                ? '<label>Stellar tx hash<input type="text" id="refund-hash" class="mono"></label>'
                : '') +
            '<label>Note<textarea id="refund-note" rows="2"></textarea></label>';
        Modal.open({
            title: 'Refund — ' + action,
            bodyHtml: body,
            confirmLabel: action,
            onConfirm: function (dialog, helpers) {
                var payload = { action: action };
                if (needsHash) {
                    payload.stellar_tx_hash = dialog.querySelector('#refund-hash').value.trim();
                }
                var note = dialog.querySelector('#refund-note').value.trim();
                if (note) payload.note = note;
                API.setButtonLoading(helpers.button, true);
                API.post('/admin/exchange-reserve/refunds/' + encodeURIComponent(refundId) +
                    '/resolve', payload)
                    .then(function (res) {
                        Router.showToast((res && res.message) || 'Refund resolved', 'success');
                        helpers.close();
                        refreshAll();
                    })
                    .catch(function (err) { Router.showToast('Error: ' + err.message, 'alert'); })
                    .then(function () { API.setButtonLoading(helpers.button, false); });
            }
        });
    }

    /* ---- replenishment ------------------------------------------------------ */

    function loadReplenishment() {
        return API.get('/admin/exchange-reserve/replenishment').then(function (res) {
            state.replenishment = res;
            renderReplenishment();
        });
    }

    function renderReplenishment() {
        var res = state.replenishment;
        var html = '<div class="table-wrap"><table><thead><tr>' +
            '<th>Kind</th><th>Enabled</th><th>Per cycle</th><th>Daily cap</th>' +
            '<th>Min float</th><th></th></tr></thead><tbody>';
        (res.policies || []).forEach(function (p) {
            // 0 means unconfigured, which is NOT the same as unlimited.
            var unset = p.max_spend_minor === 0 || p.daily_spend_cap_minor === 0;
            var badge = p.enabled
                ? '<span class="badge ok">enabled</span>'
                : '<span class="badge neutral">disabled</span>';
            if (unset) badge += ' <span class="badge pending">caps unset</span>';
            // Every cap is denominated in the kind's SPEND asset (replenish.rs
            // checks them against spend_available); an unknown kind has no
            // leg to scale by and renders raw.
            var legs = ReserveMath.replenishLegs(p.kind);
            var spend = legs ? legs.spend : null;
            var unit = spend ? ' ' + escapeHtml(spend) : '';
            html += '<tr><td class="mono">' + escapeHtml(p.kind) + '</td>' +
                '<td>' + badge + '</td>' +
                '<td>' + money(p.max_spend_minor, spend) + unit + '</td>' +
                '<td>' + money(p.daily_spend_cap_minor, spend) + unit + '</td>' +
                '<td>' + money(p.min_float_minor, spend) + unit + '</td>' +
                '<td>' + (canManage
                    ? '<button type="button" class="button tiny replenish-run" data-kind="' +
                      escapeHtml(p.kind) + '">Run now</button>'
                    : '') + '</td></tr>';
        });
        html += '</tbody></table></div>';

        var cycles = res.cycles || [];
        if (cycles.length) {
            html += '<h6>Recent cycles</h6><div class="table-wrap"><table><thead><tr>' +
                '<th>When</th><th>Kind</th><th>State</th><th>Spend</th>' +
                '<th>Received</th><th>Detail</th><th></th></tr></thead><tbody>';
            cycles.forEach(function (c) {
                // A refunded cycle got its SPEND asset back, not the recv
                // asset: scale and label the arrival accordingly.
                var arrival = ReserveMath.cycleArrivalCurrency(c);
                var got = c.actual_recv_minor !== null && c.actual_recv_minor !== undefined
                    ? money(c.actual_recv_minor, arrival) + ' ' + escapeHtml(arrival)
                    : '—';
                var action = c.state === 'in_transit' && canManage
                    ? '<button type="button" class="button tiny cycle-confirm" data-id="' +
                      escapeHtml(c.cycle_id) + '">Confirm receipt</button>'
                    : '';
                html += '<tr><td>' + escapeHtml(c.created_at) + '</td>' +
                    '<td class="mono">' + escapeHtml(c.kind) + '</td>' +
                    '<td><span class="badge ' + ReserveMath.cycleBadge(c.state) + '">' +
                    escapeHtml(c.state) + '</span></td>' +
                    '<td>' + money(c.spend_minor, c.spend_currency) + ' ' +
                    escapeHtml(c.spend_currency) + '</td>' +
                    '<td>' + got + '</td>' +
                    '<td>' + escapeHtml(c.last_error || c.quote_pricing || '') + '</td>' +
                    '<td>' + action + '</td></tr>';
            });
            html += '</tbody></table></div>';
        }

        var container = document.getElementById('reserve-replenishment');
        container.innerHTML = html;
        container.querySelectorAll('.replenish-run').forEach(function (btn) {
            btn.addEventListener('click', function () {
                runReplenishment(btn.getAttribute('data-kind'), btn);
            });
        });
        container.querySelectorAll('.cycle-confirm').forEach(function (btn) {
            btn.addEventListener('click', function () {
                openConfirmFiatModal(btn.getAttribute('data-id'));
            });
        });
    }

    // A replenishment cycle SPENDS real reserve funds the moment the bridge
    // accepts it, so a bare one-click table button is not enough: confirm
    // with the kind and the active network named — the same discipline every
    // other money mutation on this page already gets.
    function runReplenishment(kind, btn) {
        var network = (typeof API.currentNetworkKey === 'function' && API.currentNetworkKey()) || 'unknown';
        Modal.open({
            title: 'Run a replenishment cycle now?',
            bodyHtml:
                '<p>This starts a <span class="mono">' + escapeHtml(kind) + '</span> cycle on ' +
                '<strong>' + escapeHtml(network) + '</strong>. The bridge will spend reserve funds ' +
                'up to the per-cycle cap immediately; there is no undo once the transfer is sent.</p>',
            confirmLabel: 'Run cycle',
            onConfirm: function (dialog, helpers) {
                API.setButtonLoading(btn, true);
                API.post('/admin/exchange-reserve/replenishment/run', { kind: kind })
                    .then(function (res) {
                        Router.showToast((res && res.message) || 'Cycle requested', 'success');
                        helpers.close();
                        refreshAll();
                    })
                    .catch(function (err) {
                        Router.showToast('Error: ' + err.message, 'alert');
                        helpers.close();
                    })
                    .then(function () { API.setButtonLoading(btn, false); });
            }
        });
    }

    function openConfirmFiatModal(cycleId) {
        var body =
            '<p class="text-muted">The bridge can see the USDC leave and the provider&rsquo;s status, but never a bank credit. Confirm only what you have actually seen on the statement.</p>' +
            '<label>Amount received (USD, optional override)<input type="text" id="fiat-amount"></label>' +
            '<label>Bank reference<input type="text" id="fiat-ref"></label>' +
            '<label>Note<textarea id="fiat-note" rows="2"></textarea></label>' +
            '<p class="form-error" id="fiat-error" hidden></p>';
        Modal.open({
            title: 'Confirm bank receipt',
            bodyHtml: body,
            confirmLabel: 'Confirm receipt',
            onConfirm: function (dialog, helpers) {
                var payload = {};
                var raw = dialog.querySelector('#fiat-amount').value.trim();
                if (raw) {
                    var check = ReserveMath.validateAmount(raw, 2);
                    if (!check.ok) {
                        var errEl = dialog.querySelector('#fiat-error');
                        errEl.textContent = check.error;
                        errEl.hidden = false;
                        return;
                    }
                    payload.amount_usd_cents = check.minor;
                }
                var ref = dialog.querySelector('#fiat-ref').value.trim();
                if (ref) payload.external_ref = ref;
                var note = dialog.querySelector('#fiat-note').value.trim();
                if (note) payload.note = note;
                API.setButtonLoading(helpers.button, true);
                API.post('/admin/exchange-reserve/replenishment/' +
                    encodeURIComponent(cycleId) + '/confirm-fiat', payload)
                    .then(function (res) {
                        Router.showToast((res && res.message) || 'Confirmed', 'success');
                        helpers.close();
                        refreshAll();
                    })
                    .catch(function (err) { Router.showToast('Error: ' + err.message, 'alert'); })
                    .then(function () { API.setButtonLoading(helpers.button, false); });
            }
        });
    }

    /* ---- boot ------------------------------------------------------------- */

    function showError(err) {
        Router.showToast('Error: ' + err.message, 'alert');
    }

    /** Wrap a section loader so a failure replaces its loading placeholder. */
    function sectionLoad(id, loader) {
        return function () {
            return loader().catch(function (err) {
                document.getElementById(id).innerHTML =
                    '<p class="text-muted">Could not load: ' + escapeHtml(err.message) + '</p>';
                throw err;
            });
        };
    }

    function refreshAll() {
        // Status first: it is the only call that returns the bucket scales,
        // and /admin/exchange-reserve waits on a Horizon round-trip while the
        // ledger is one query, so unordered loads painted USD rows at 7 dp
        // on essentially every visit. The scaled sections drop their cached
        // payloads (a post-action refresh must not flash pre-action rows)
        // and show a loading state until status settles (a Horizon hang can
        // hold it for up to ~30s); the forecast depends on status for the
        // bucket badges.
        state.ledger = null;
        state.refunds = null;
        state.replenishment = null;
        showLoading(SCALED_SECTIONS);
        return ReserveMath.sequenceLoads(
            loadStatus,
            [
                loadForecast,
                sectionLoad('reserve-ledger', loadLedger),
                sectionLoad('reserve-refunds', loadRefunds),
                sectionLoad('reserve-replenishment', loadReplenishment)
            ],
            [loadQueues, loadUnmatched],
            showError
        );
    }

    var kindSelect = document.getElementById('ledger-kind');
    ENTRY_KINDS.forEach(function (k) {
        var opt = document.createElement('option');
        opt.value = k;
        opt.textContent = k;
        kindSelect.appendChild(opt);
    });
    kindSelect.addEventListener('change', function () {
        state.ledgerPage = 1;
        loadLedger().catch(showError);
    });
    document.getElementById('forecast-window').addEventListener('change', function () {
        loadForecast().catch(showError);
    });
    // Hidden via data-permission for read-only viewers; wire null-safely.
    var entryBtn = document.getElementById('entry-btn');
    if (canManage && entryBtn) entryBtn.addEventListener('click', openEntryModal);

    if (!canManage) {
        Router.showReadOnlyBanner('Reserve actions', 'the admin or treasurer role');
    }

    refreshAll();
})();
