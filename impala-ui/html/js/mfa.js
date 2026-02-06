/**
 * MFA page module — lookup, enroll, and verify multi-factor authentication.
 *
 * Supports two MFA types:
 *  - TOTP: requires a shared secret for enrollment
 *  - SMS: requires a phone number for enrollment
 *
 * Enrollment uses POST /mfa with UPSERT semantics (re-enrollment replaces
 * existing method). Verification uses POST /mfa/verify.
 */
(function () {
    Router.init();

    var lookupBtn = document.getElementById('mfa-lookup-btn');
    var lookupInput = document.getElementById('mfa-lookup-id');
    var enrollmentsDiv = document.getElementById('mfa-enrollments');
    var enrollForm = document.getElementById('enroll-form');
    var verifyForm = document.getElementById('verify-form');
    var mfaTypeSelect = document.getElementById('enroll-mfa-type');
    var totpField = document.getElementById('totp-field');
    var smsField = document.getElementById('sms-field');

    // Toggle TOTP/SMS fields
    mfaTypeSelect.addEventListener('change', function () {
        if (this.value === 'sms') {
            totpField.classList.add('hidden');
            smsField.classList.remove('hidden');
        } else {
            totpField.classList.remove('hidden');
            smsField.classList.add('hidden');
        }
    });

    // Lookup
    lookupBtn.addEventListener('click', doLookup);
    lookupInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') doLookup();
    });

    function doLookup() {
        var id = lookupInput.value.trim();
        if (!id) return;

        enrollmentsDiv.innerHTML = '<div class="spinner"></div> Loading...';

        API.get('/mfa?account_id=' + encodeURIComponent(id))
            .then(function (data) {
                var items = Array.isArray(data) ? data : [data];
                if (items.length === 0) {
                    enrollmentsDiv.innerHTML = '<div class="callout primary">No MFA enrollments found.</div>';
                    return;
                }

                var html = '<table><thead><tr>' +
                    '<th>Type</th><th>Status</th><th>Created</th>' +
                    '</tr></thead><tbody>';

                items.forEach(function (item) {
                    html += '<tr>' +
                        '<td>' + escapeHtml(item.mfa_type || '') + '</td>' +
                        '<td>' + escapeHtml(item.status || item.verified ? 'Verified' : 'Pending') + '</td>' +
                        '<td>' + escapeHtml(item.created_at || '') + '</td>' +
                        '</tr>';
                });
                html += '</tbody></table>';
                enrollmentsDiv.innerHTML = html;
            })
            .catch(function (err) {
                enrollmentsDiv.innerHTML = '<div class="callout warning">' + escapeHtml(err.message) + '</div>';
            });
    }

    // Enroll
    enrollForm.addEventListener('submit', function (e) {
        e.preventDefault();
        var body = {
            account_id: document.getElementById('enroll-account-id').value.trim(),
            mfa_type: mfaTypeSelect.value
        };

        if (mfaTypeSelect.value === 'totp') {
            body.secret = document.getElementById('enroll-secret').value.trim();
        } else {
            body.phone = document.getElementById('enroll-phone').value.trim();
        }

        API.post('/mfa', body)
            .then(function (data) {
                Router.showToast('MFA enrolled successfully', 'success');
                enrollForm.reset();
                // Reset field visibility
                totpField.classList.remove('hidden');
                smsField.classList.add('hidden');
            })
            .catch(function (err) {
                Router.showToast('Error: ' + err.message, 'alert');
            });
    });

    // Verify
    verifyForm.addEventListener('submit', function (e) {
        e.preventDefault();
        var submitBtn = verifyForm.querySelector('button[type="submit"]');
        if (submitBtn) submitBtn.disabled = true;

        var body = {
            account_id: document.getElementById('verify-account-id').value.trim(),
            mfa_type: document.getElementById('verify-mfa-type').value,
            code: document.getElementById('verify-code').value.trim()
        };

        API.post('/mfa/verify', body)
            .then(function () {
                Router.showToast('MFA verified successfully', 'success');
                verifyForm.reset();
            })
            .catch(function (err) {
                Router.showToast('Verification failed: ' + err.message, 'alert');
            })
            .then(function () {
                if (submitBtn) submitBtn.disabled = false;
            });
    });

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }
})();
