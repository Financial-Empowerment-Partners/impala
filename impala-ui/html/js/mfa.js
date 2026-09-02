/**
 * MFA page module — lookup, enroll, and verify multi-factor authentication.
 *
 * Supports two MFA types:
 *  - TOTP: requires a shared secret for enrollment
 *  - SMS: requires a phone number for enrollment
 *
 * Enrollment uses POST /mfa with UPSERT semantics (re-enrollment replaces
 * existing method). Verification uses POST /mfa/verify.
 * Validates TOTP codes (6 digits) and phone numbers (E.164) before submission.
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
        if (!id) {
            Router.showToast('Please enter an account ID', 'warning');
            return;
        }

        var check = Validate.required(id);
        if (!check.valid) {
            Router.showToast(check.message, 'warning');
            return;
        }

        API.setButtonLoading(lookupBtn, true);
        enrollmentsDiv.innerHTML = '<div class="spinner"></div> Loading...';

        API.get('/mfa?account_id=' + encodeURIComponent(id))
            .then(function (data) {
                var items = Array.isArray(data) ? data : [data];
                if (items.length === 0) {
                    enrollmentsDiv.innerHTML = '<div class="callout primary">No MFA enrollments found.</div>';
                    return;
                }

                // The bridge returns {mfa_type, enabled, configured} per
                // enrollment (no status/verified/created_at). The old render
                // referenced fields that never exist and mis-grouped
                // `item.status || item.verified ? ...` so every row read
                // "Pending" with a blank date.
                var html = '<table><thead><tr>' +
                    '<th>Type</th><th>Status</th><th>Secret</th>' +
                    '</tr></thead><tbody>';

                items.forEach(function (item) {
                    html += '<tr>' +
                        '<td>' + escapeHtml(item.mfa_type || '') + '</td>' +
                        '<td>' + (item.enabled ? 'Enabled' : 'Disabled') + '</td>' +
                        '<td>' + (item.configured ? 'Configured' : 'Not configured') + '</td>' +
                        '</tr>';
                });
                html += '</tbody></table>';
                enrollmentsDiv.innerHTML = html;
            })
            .catch(function (err) {
                enrollmentsDiv.innerHTML = '<div class="callout warning">' + escapeHtml(err.message) + '</div>';
            })
            .then(function () {
                API.setButtonLoading(lookupBtn, false);
            });
    }

    // Enroll
    enrollForm.addEventListener('submit', function (e) {
        e.preventDefault();

        var accountId = document.getElementById('enroll-account-id').value.trim();

        var error = Validate.firstError([
            Validate.required(accountId)
        ]);
        if (error) {
            Router.showToast(error, 'warning');
            return;
        }

        var body = {
            account_id: accountId,
            mfa_type: mfaTypeSelect.value
        };

        // TOTP secrets are generated server-side; the client sends none. SMS
        // needs a phone number, and the bridge's field is `phone_number`
        // (the old `phone` key was silently dropped, so SMS enrollment always
        // returned success:false while the UI toasted success).
        if (mfaTypeSelect.value === 'sms') {
            var phone = document.getElementById('enroll-phone').value.trim();
            var phoneCheck = Validate.phone(phone);
            if (!phoneCheck.valid) {
                Router.showToast(phoneCheck.message, 'warning');
                return;
            }
            body.phone_number = phone;
        }

        var submitBtn = enrollForm.querySelector('button[type="submit"]');
        API.setButtonLoading(submitBtn, true);
        var resultDiv = document.getElementById('enroll-result');
        if (resultDiv) resultDiv.classList.add('hidden');

        API.post('/mfa', body)
            .then(function (data) {
                // Honor the success envelope: a 200 can still be a failure.
                if (data && data.success === false) {
                    Router.showToast(data.message || 'Enrollment failed', 'alert');
                    return;
                }
                Router.showToast('MFA enrolled successfully', 'success');
                // Surface the TOTP setup link so the operator can register it
                // in an authenticator — without it, TOTP MFA is unusable.
                if (resultDiv && data && data.provisioning_uri) {
                    resultDiv.textContent = 'Add this to your authenticator: ' + data.provisioning_uri;
                    resultDiv.classList.remove('hidden');
                }
                enrollForm.reset();
                // Reset field visibility
                totpField.classList.remove('hidden');
                smsField.classList.add('hidden');
            })
            .catch(function (err) {
                Router.showToast('Error: ' + err.message, 'alert');
            })
            .then(function () {
                API.setButtonLoading(submitBtn, false);
            });
    });

    // Verify
    verifyForm.addEventListener('submit', function (e) {
        e.preventDefault();

        var accountId = document.getElementById('verify-account-id').value.trim();
        var code = document.getElementById('verify-code').value.trim();
        var mfaType = document.getElementById('verify-mfa-type').value;

        // Validate TOTP code format
        var validations = [Validate.required(accountId)];
        if (mfaType === 'totp') {
            validations.push(Validate.totpCode(code));
        } else {
            validations.push(Validate.required(code));
        }

        var error = Validate.firstError(validations);
        if (error) {
            Router.showToast(error, 'warning');
            return;
        }

        var submitBtn = verifyForm.querySelector('button[type="submit"]');
        API.setButtonLoading(submitBtn, true);

        var body = {
            account_id: accountId,
            mfa_type: mfaType,
            code: code
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
                API.setButtonLoading(submitBtn, false);
            });
    });

    // Delegates to the shared escaper: a text-node round trip escapes & < >
    // but NOT quotes, so values interpolated into double-quoted attributes
    // (value="...", title="...") could break out and inject attributes.
    function escapeHtml(str) {
        return EscapeHtml.escape(str);
    }
})();
