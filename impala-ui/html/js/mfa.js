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

        if (mfaTypeSelect.value === 'totp') {
            var secret = document.getElementById('enroll-secret').value.trim();
            var secretCheck = Validate.required(secret);
            if (!secretCheck.valid) {
                Router.showToast('TOTP secret is required', 'warning');
                return;
            }
            body.secret = secret;
        } else {
            var phone = document.getElementById('enroll-phone').value.trim();
            var phoneCheck = Validate.phone(phone);
            if (!phoneCheck.valid) {
                Router.showToast(phoneCheck.message, 'warning');
                return;
            }
            body.phone = phone;
        }

        var submitBtn = enrollForm.querySelector('button[type="submit"]');
        API.setButtonLoading(submitBtn, true);

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

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }
})();
