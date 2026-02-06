/**
 * Transactions page module — submit transactions and maintain a session log.
 *
 * Transactions are submitted via POST /subscribe. A session-scoped log
 * (stored in sessionStorage) tracks all submissions with their status.
 * The log is cleared when the browser tab closes.
 */
(function () {
    Router.init();

    var txForm = document.getElementById('tx-form');
    var txLog = document.getElementById('tx-log');
    var LOG_KEY = 'impala_tx_log';

    // Load existing session log
    renderLog();

    txForm.addEventListener('submit', function (e) {
        e.preventDefault();

        var body = {
            source_account: document.getElementById('tx-source').value.trim(),
            destination_account: document.getElementById('tx-destination').value.trim(),
            amount: document.getElementById('tx-amount').value.trim(),
            asset_code: document.getElementById('tx-asset-code').value.trim() || undefined,
            memo: document.getElementById('tx-memo').value.trim() || undefined
        };

        var submitBtn = txForm.querySelector('button[type="submit"]');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Submitting...';

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
                submitBtn.disabled = false;
                submitBtn.textContent = 'Submit Transaction';
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
        sessionStorage.setItem(LOG_KEY, JSON.stringify(log));
        renderLog();
    }

    function renderLog() {
        var log = getLog();
        if (log.length === 0) {
            txLog.innerHTML = '<p class="text-center" style="color:#666;">No transactions in this session.</p>';
            return;
        }

        var html = '<table><thead><tr>' +
            '<th>Time</th><th>Source</th><th>Dest</th><th>Amount</th><th>Asset</th><th>Status</th>' +
            '</tr></thead><tbody>';

        log.forEach(function (entry) {
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
        txLog.innerHTML = html;
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
