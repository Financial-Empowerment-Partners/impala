/**
 * Transactions console — submit transactions and review the server-backed log.
 *
 * The create form still posts to POST /subscribe (create_transactions). The log
 * is now a server-paged table from GET /transactions with a filter bar (status /
 * flagged / date range / free-text), flag & status badges, and a Review action
 * (review_transactions) that opens a modal posting to PUT /transaction/:btxid/review.
 */
(function () {
    Router.init();

    var PAGE_SIZE = 10;
    var currentPage = 1;
    var STATUS_VALUES = ['unreviewed', 'cleared', 'flagged', 'escalated'];

    var txForm = document.getElementById('tx-form');
    var listContainer = document.getElementById('tx-list');
    var paginationContainer = 'tx-pagination';
    var applyBtn = document.getElementById('tx-filter-apply');
    var resetBtn = document.getElementById('tx-filter-reset');

    if (txForm) {
        txForm.addEventListener('submit', onCreate);
    }
    if (applyBtn) {
        applyBtn.addEventListener('click', function () { currentPage = 1; loadList(); });
    }
    if (resetBtn) {
        resetBtn.addEventListener('click', function () {
            setVal('tx-filter-status', '');
            setVal('tx-filter-flagged', '');
            setVal('tx-filter-from', '');
            setVal('tx-filter-to', '');
            setVal('tx-filter-q', '');
            currentPage = 1;
            loadList();
        });
    }

    loadList();

    /* ---- create ---------------------------------------------------------- */

    function onCreate(e) {
        e.preventDefault();
        var source = document.getElementById('tx-source').value.trim();
        var destination = document.getElementById('tx-destination').value.trim();
        var amount = document.getElementById('tx-amount').value.trim();

        var error = Validate.firstError([
            Validate.stellarId(source),
            Validate.stellarId(destination),
            Validate.positiveNumber(amount)
        ]);
        if (error) { Router.showToast(error, 'warning'); return; }

        // NOTE: there is no bridge endpoint that builds and submits a payment
        // from (source, destination, amount). The old code POSTed this
        // payment-shaped body to /subscribe (an admin stream-subscription
        // endpoint), which simply 422'd — it never moved funds, but it read
        // like a working "submit" button. `POST /transaction` only *records*
        // an already-executed transaction (stellar_tx_id/hash), a different
        // contract. Rather than silently mis-call an endpoint, this reports
        // the gap honestly. Building payments belongs to the signing clients
        // (lumencli / impalactl / the card), not this read-and-review console.
        Router.showToast(
            'Submitting payments from the admin console is not supported — build and sign ' +
            'transactions with lumencli, impalactl, or a card. This page lists and reviews them.',
            'warning'
        );
    }

    /* ---- list ------------------------------------------------------------ */

    function currentFilters() {
        return {
            page: currentPage,
            per_page: PAGE_SIZE,
            status: getVal('tx-filter-status'),
            flagged: getVal('tx-filter-flagged'),
            from: toRfc3339(getVal('tx-filter-from'), false),
            to: toRfc3339(getVal('tx-filter-to'), true),
            q: getVal('tx-filter-q')
        };
    }

    function loadList() {
        renderSkeleton();
        var qs = TxFilter.buildQuery(currentFilters());
        API.get('/transactions' + (qs ? '?' + qs : ''))
            .then(function (resp) { renderTable(resp); })
            .catch(function (err) {
                listContainer.innerHTML = '<div class="callout alert">' + escapeHtml(err.message) + '</div>';
                clearPagination();
            });
    }

    function renderSkeleton() {
        var rows = '';
        for (var i = 0; i < 5; i++) rows += '<div class="skeleton skeleton-row"></div>';
        listContainer.innerHTML = rows;
        clearPagination();
    }

    function renderTable(resp) {
        var items = (resp && resp.data) || [];
        var total = (resp && typeof resp.total === 'number') ? resp.total : items.length;

        if (items.length === 0) {
            listContainer.innerHTML = emptyState('🧾', 'No transactions', 'No transactions match the current filters.');
            clearPagination();
            return;
        }

        var canReview = Roles.currentUserHasPermission('review_transactions');

        var html = '<div class="table-wrap"><table><thead><tr>' +
            '<th>Created</th><th>Btxid</th><th>Source</th><th>Currency</th><th>Fee</th><th>Status</th><th>Flag</th>' +
            (canReview ? '<th>Actions</th>' : '') +
            '</tr></thead><tbody>';

        items.forEach(function (t, idx) {
            html += '<tr>' +
                '<td class="nowrap">' + escapeHtml(formatDate(t.created_at)) + '</td>' +
                '<td class="mono" title="' + escapeHtml(t.btxid || '') + '">' + escapeHtml(truncate(t.btxid, 10)) + '</td>' +
                '<td class="mono nowrap" title="' + escapeHtml(t.source_account || '') + '">' + escapeHtml(truncate(t.source_account, 12)) + '</td>' +
                '<td>' + escapeHtml(t.payala_currency || '') + '</td>' +
                '<td class="mono">' + escapeHtml(t.stellar_fee == null ? '' : String(t.stellar_fee)) + '</td>' +
                '<td>' + statusBadge(t.status) + '</td>' +
                '<td>' + (t.flagged ? '<span class="badge flagged">Flagged</span>' : '<span class="badge neutral">—</span>') + '</td>' +
                (canReview ? '<td><button class="button ghost tiny review-btn" data-idx="' + idx + '">Review</button></td>' : '') +
                '</tr>';
        });

        html += '</tbody></table></div>';
        listContainer.innerHTML = html;

        if (canReview) {
            var btns = listContainer.querySelectorAll('.review-btn');
            for (var i = 0; i < btns.length; i++) {
                btns[i].addEventListener('click', function () {
                    var t = items[parseInt(this.getAttribute('data-idx'), 10)];
                    if (t) openReviewModal(t);
                });
            }
        }

        var totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        var info = { page: currentPage, pageSize: PAGE_SIZE, totalPages: totalPages, totalItems: total };
        Paginate.renderControls(info, paginationContainer, function (newPage) {
            currentPage = newPage;
            loadList();
        });
    }

    /* ---- review ---------------------------------------------------------- */

    function openReviewModal(t) {
        var statusOpts = STATUS_VALUES.map(function (s) {
            var selected = (t.status || 'unreviewed') === s ? ' selected' : '';
            return '<option value="' + s + '"' + selected + '>' + escapeHtml(s) + '</option>';
        }).join('');

        var body =
            '<dl class="detail-grid">' +
            '<dt>Btxid</dt><dd class="mono">' + escapeHtml(t.btxid || '') + '</dd>' +
            '<dt>Source</dt><dd class="mono">' + escapeHtml(t.source_account || '') + '</dd>' +
            '</dl>' +
            '<label><input type="checkbox" id="review-flagged"' + (t.flagged ? ' checked' : '') + '> Flagged</label>' +
            '<label>Status<select id="review-status">' + statusOpts + '</select></label>' +
            '<label>Note<textarea id="review-note" rows="3" placeholder="Reviewer note (optional)">' + escapeHtml(t.note || '') + '</textarea></label>';

        Modal.open({
            title: 'Review transaction',
            bodyHtml: body,
            confirmLabel: 'Save review',
            onConfirm: function (dialog, helpers) {
                var payload = {
                    flagged: dialog.querySelector('#review-flagged').checked,
                    status: dialog.querySelector('#review-status').value,
                    note: dialog.querySelector('#review-note').value.trim() || undefined
                };
                API.setButtonLoading(helpers.button, true);
                API.put('/transaction/' + encodeURIComponent(t.btxid) + '/review', payload)
                    .then(function (res) {
                        Router.showToast((res && res.message) || 'Review saved', 'success');
                        helpers.close();
                        loadList();
                    })
                    .catch(function (err) { Router.showToast('Error: ' + err.message, 'alert'); })
                    .then(function () { API.setButtonLoading(helpers.button, false); });
            }
        });
    }

    /* ---- helpers --------------------------------------------------------- */

    function statusBadge(status) {
        status = status || 'unreviewed';
        var cls = STATUS_VALUES.indexOf(status) !== -1 ? status : 'neutral';
        return '<span class="badge ' + cls + '">' + escapeHtml(status) + '</span>';
    }

    function toRfc3339(dateStr, endOfDay) {
        if (!dateStr) return '';
        // <input type="date"> yields YYYY-MM-DD; widen to a full RFC3339 instant.
        if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
            return dateStr + (endOfDay ? 'T23:59:59Z' : 'T00:00:00Z');
        }
        return dateStr;
    }

    function getVal(id) {
        var el = document.getElementById(id);
        return el ? el.value.trim() : '';
    }

    function setVal(id, value) {
        var el = document.getElementById(id);
        if (el) el.value = value;
    }

    function clearPagination() {
        var pag = document.getElementById(paginationContainer);
        if (pag) pag.innerHTML = '';
    }

    function emptyState(icon, title, msg) {
        return '<div class="empty-state"><span class="empty-icon" aria-hidden="true">' + icon + '</span>' +
            '<h6>' + escapeHtml(title) + '</h6><p>' + escapeHtml(msg) + '</p></div>';
    }

    function truncate(str, len) {
        if (!str) return '';
        return str.length > len ? str.substring(0, len) + '…' : str;
    }

    function formatDate(value) {
        if (!value) return '';
        var d = new Date(value);
        return isNaN(d.getTime()) ? String(value) : d.toLocaleString();
    }

    // Delegates to the shared escaper: a text-node round trip escapes & < >
    // but NOT quotes, so values interpolated into double-quoted attributes
    // (value="...", title="...") could break out and inject attributes.
    function escapeHtml(str) {
        return EscapeHtml.escape(str);
    }
})();
