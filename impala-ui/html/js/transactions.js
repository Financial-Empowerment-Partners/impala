/**
 * Transactions page module — submit transactions and maintain a session log.
 *
 * Transactions are submitted via POST /subscribe. A session-scoped log
 * (stored in sessionStorage) tracks all submissions with their status.
 * The log is cleared when the browser tab closes. Capped at 100 entries.
 * Supports client-side pagination of the transaction log.
 */
(function () {
    Router.init();

    var txForm = document.getElementById('tx-form');
    var txLog = document.getElementById('tx-log');
    var LOG_KEY = 'impala_tx_log';
    var LOG_MAX = 100;
    var PAGE_SIZE = 10;
    var currentPage = 1;

    // Load existing session log
    renderLog();

    txForm.addEventListener('submit', function (e) {
        e.preventDefault();

        var source = document.getElementById('tx-source').value.trim();
        var destination = document.getElementById('tx-destination').value.trim();
        var amount = document.getElementById('tx-amount').value.trim();

        // Validate inputs
        var error = Validate.firstError([
            Validate.stellarId(source),
            Validate.stellarId(destination),
            Validate.positiveNumber(amount)
        ]);
        if (error) {
            Router.showToast(error, 'warning');
            return;
        }

        var body = {
            source_account: source,
            destination_account: destination,
            amount: amount,
            asset_code: document.getElementById('tx-asset-code').value.trim() || undefined,
            memo: document.getElementById('tx-memo').value.trim() || undefined
        };

        var submitBtn = txForm.querySelector('button[type="submit"]');
        API.setButtonLoading(submitBtn, true);

        API.post('/subscribe', body)
            .then(function (data) {
                Router.showToast('Transaction submitted', 'success');
                addToLog(body, data);
                txForm.reset();
            })
            .catch(function (err) {
                Router.showToast('Error: ' + err.message, 'alert');
                addToLog(body, { error: err.message });
            })
            .then(function () {
                API.setButtonLoading(submitBtn, false);
            });
    });

    function getLog() {
        try {
            return JSON.parse(sessionStorage.getItem(LOG_KEY)) || [];
        } catch (e) {
            return [];
        }
    }

    function addToLog(request, response) {
        var log = getLog();
        log.unshift({
            timestamp: new Date().toISOString(),
            source: request.source_account,
            destination: request.destination_account,
            amount: request.amount,
            asset_code: request.asset_code || 'N/A',
            status: response.error ? 'Error' : 'Submitted',
            detail: response.error || 'OK'
        });

        // Cap at LOG_MAX entries
        if (log.length > LOG_MAX) {
            log = log.slice(0, LOG_MAX);
        }

        sessionStorage.setItem(LOG_KEY, JSON.stringify(log));
        currentPage = 1;
        renderLog();
    }

    function renderLog() {
        var log = getLog();
        if (log.length === 0) {
            txLog.innerHTML = '<p class="text-center" style="color:#666;">No transactions in this session.</p>';
            return;
        }

        var info = Paginate.paginate(log, currentPage, PAGE_SIZE);

        var html = '<table><thead><tr>' +
            '<th>Time</th><th>Source</th><th>Dest</th><th>Amount</th><th>Asset</th><th>Status</th>' +
            '</tr></thead><tbody>';

        info.items.forEach(function (entry) {
            var statusClass = entry.status === 'Error' ? 'error' : 'ok';
            html += '<tr>' +
                '<td>' + escapeHtml(new Date(entry.timestamp).toLocaleTimeString()) + '</td>' +
                '<td>' + escapeHtml(truncate(entry.source, 16)) + '</td>' +
                '<td>' + escapeHtml(truncate(entry.destination, 16)) + '</td>' +
                '<td>' + escapeHtml(entry.amount) + '</td>' +
                '<td>' + escapeHtml(entry.asset_code) + '</td>' +
                '<td><span class="badge ' + statusClass + '">' + escapeHtml(entry.status) + '</span></td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        html += '<div id="tx-log-pagination"></div>';
        txLog.innerHTML = html;

        Paginate.renderControls(info, 'tx-log-pagination', function (newPage) {
            currentPage = newPage;
            renderLog();
        });
    }

    function truncate(str, len) {
        if (!str) return '';
        return str.length > len ? str.substring(0, len) + '...' : str;
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }
})();
