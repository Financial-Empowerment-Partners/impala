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

    // ── This session's MFA standing + step-up (docs/mfa-card-pin-biometrics.md §5) ──
    var statusDiv = document.getElementById('mfa-status');
    var stepUpForm = document.getElementById('stepup-form');

    function chipsHtml(chips) {
        return chips.map(function (c) {
            return '<span class="badge ' + c.cls + '">' + escapeHtml(c.label) + '</span>';
        }).join(' ');
    }

    function loadStatus() {
        if (!statusDiv) return;
        statusDiv.innerHTML = '<div class="spinner"></div> Loading…';
        API.get('/mfa/status')
            .then(function (data) {
                var status = MfaAdminView.normalizeStatus(data);
                var sum = MfaAdminView.sessionSummary(status);
                var chips = MfaAdminView.factorChips(status.amr);
                var html = '<p><span class="badge ' + sum.badge.cls + '">' +
                    escapeHtml(sum.badge.label) + '</span> ' + escapeHtml(sum.text) + '</p>';
                if (chips.length) html += '<p>Verified: ' + chipsHtml(chips) + '</p>';
                statusDiv.innerHTML = html;
                if (stepUpForm) stepUpForm.classList.toggle('hidden', !sum.needsStepUp);
            })
            .catch(function (err) {
                var c = MfaAdminView.classifyLoadError(err);
                statusDiv.innerHTML = '<div class="callout warning">' + escapeHtml(c.message) + '</div>';
                if (stepUpForm) stepUpForm.classList.add('hidden');
            });
    }

    if (stepUpForm) {
        stepUpForm.addEventListener('submit', function (e) {
            e.preventDefault();
            var codeInput = document.getElementById('stepup-code');
            var code = codeInput ? codeInput.value.trim() : '';
            var codeCheck = Validate.totpCode(code);
            if (!codeCheck.valid) {
                Router.showToast(codeCheck.message, 'warning');
                return;
            }
            var btn = stepUpForm.querySelector('button[type="submit"]');
            API.setButtonLoading(btn, true);
            // postCredential: a refused code (401) is an answer about the code, not the session.
            API.postCredential('/mfa/step-up', MfaAdminView.totpStepUpBody(code))
                .then(function (res) {
                    // A bearer session comes back as a new token family and the one that asked is
                    // revoked: store it before anything else is requested. A cookie session is
                    // upgraded in place and has nothing to store.
                    var tokens = MfaAdminView.stepUpTokens(res);
                    if (tokens) API.setTokens(tokens.temporal, tokens.refresh);
                    Router.showToast('Step-up complete', 'success');
                    stepUpForm.reset();
                    loadStatus();
                })
                .catch(function (err) {
                    Router.showToast(MfaAdminView.stepUpErrorMessage(err), 'alert');
                    // An ordinary request settles whether the session itself is still good
                    // (it refreshes a stale token, or sends a dead session to the login page).
                    if (err && err.status === 401) loadStatus();
                })
                .then(function () { API.setButtonLoading(btn, false); });
        });
    }

    loadStatus();

    // ── Per-account MFA admin (factor summary, mandate, device-key recovery) ──
    var acctBtn = document.getElementById('acct-mfa-btn');
    var acctInput = document.getElementById('acct-mfa-id');
    var acctResult = document.getElementById('acct-mfa-result');

    function loadAccountMfa() {
        var id = acctInput.value.trim();
        if (!id) {
            Router.showToast('Please enter an account ID', 'warning');
            return;
        }
        API.setButtonLoading(acctBtn, true);
        acctResult.innerHTML = '<div class="spinner"></div> Loading…';
        API.get('/admin/accounts/' + encodeURIComponent(id) + '/mfa')
            .then(function (data) {
                renderAccountMfa(MfaAdminView.normalizeAccountMfa(data), id);
            })
            .catch(function (err) {
                var c = MfaAdminView.classifyLoadError(err);
                acctResult.innerHTML = '<div class="callout warning">' + escapeHtml(c.message) + '</div>';
            })
            .then(function () { API.setButtonLoading(acctBtn, false); });
    }

    function renderAccountMfa(acct, id) {
        var fs = MfaAdminView.accountFactorSummary(acct);
        var mandateOn = acct.mfaRequired === true;
        var html = '<p>Factors: ' + chipsHtml(fs.chips) + '</p>';
        html += '<p>MFA mandate: <span class="badge ' + (mandateOn ? 'ok' : 'neutral') + '">' +
            (mandateOn ? 'required' : 'not required') + '</span>';
        if (mandateOn && !fs.canBeMfa) {
            html += ' <span class="badge warning">no second factor enrolled</span>';
        }
        html += '</p>';
        // Mandate toggle (admin): turning it on signs the account out everywhere.
        html += '<button class="button" id="acct-mfa-toggle">' +
            (mandateOn ? 'Lift the MFA requirement' : 'Require MFA for this account') + '</button>';
        if (!mandateOn && !fs.canBeMfa) {
            html += '<p class="text-muted">This account has fewer than two factor kinds, so requiring ' +
                'MFA would lock it out until it enrols another. Enrol a factor first.</p>';
        }
        // Device keys with recovery delete. The key id is carried on a numeric
        // data-idx (never interpolated into an attribute); the handler reads it
        // from the array.
        if (acct.deviceKeys.length) {
            html += '<h6 style="margin-top:1rem;">Device keys</h6><table><thead><tr>' +
                '<th>Label</th><th>Platform</th><th>Verification</th><th></th></tr></thead><tbody>';
            acct.deviceKeys.forEach(function (k, idx) {
                html += '<tr><td>' + escapeHtml(k.label || '(unnamed)') + '</td>' +
                    '<td>' + escapeHtml(k.platform || '—') + '</td>' +
                    '<td>' + escapeHtml(k.userVerification) + '</td>' +
                    '<td><button class="button alert tiny acct-mfa-revoke" data-idx="' + idx +
                    '">Revoke</button></td></tr>';
            });
            html += '</tbody></table>';
        }
        acctResult.innerHTML = html;

        var toggle = document.getElementById('acct-mfa-toggle');
        if (toggle) {
            toggle.addEventListener('click', function () {
                var want = !mandateOn;
                // Either direction signs the account out everywhere: always ask.
                Modal.confirm(MfaAdminView.mandateConfirm(want, fs.canBeMfa)).then(function (ok) {
                    if (!ok) return;
                    API.setButtonLoading(toggle, true);
                    API.put('/admin/accounts/' + encodeURIComponent(id) + '/mfa-policy',
                        MfaAdminView.policyBody(want))
                        .then(function () {
                            Router.showToast(want ? 'MFA now required for this account'
                                : 'MFA requirement lifted', 'success');
                            loadAccountMfa();
                        })
                        .catch(function (err) {
                            Router.showToast(MfaAdminView.actionErrorMessage(err), 'alert');
                            API.setButtonLoading(toggle, false);
                        });
                });
            });
        }
        Array.prototype.forEach.call(acctResult.querySelectorAll('.acct-mfa-revoke'), function (b) {
            b.addEventListener('click', function () {
                var idx = parseInt(b.getAttribute('data-idx'), 10);
                var key = acct.deviceKeys[idx];
                if (!key || !key.keyId) return;
                Modal.confirm({
                    title: 'Revoke device key?',
                    message: 'The holder must enrol a new one before they can use it as a factor.'
                }).then(function (ok) {
                    if (!ok) return;
                    API.setButtonLoading(b, true);
                    API.del('/admin/accounts/' + encodeURIComponent(id) + '/mfa/device-keys/' +
                        encodeURIComponent(key.keyId))
                        .then(function () {
                            Router.showToast('Device key revoked', 'success');
                            loadAccountMfa();
                        })
                        .catch(function (err) {
                            Router.showToast(MfaAdminView.actionErrorMessage(err), 'alert');
                            API.setButtonLoading(b, false);
                        });
                });
            });
        });
    }

    if (acctBtn && acctInput) {
        acctBtn.addEventListener('click', loadAccountMfa);
        acctInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') loadAccountMfa();
        });
    }

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
