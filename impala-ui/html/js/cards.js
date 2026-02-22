/**
 * Cards page module — register and deactivate hardware smartcards.
 *
 * Registration stores the card's EC public key (and optional RSA public key)
 * linked to an account. Deactivation uses a confirmation modal (Foundation JS
 * if available, CSS fallback otherwise) before sending a PUT with card_active: false.
 * Validates hex public keys before submission.
 */
(function () {
    Router.init();

    var registerForm = document.getElementById('register-form');
    var deactBtn = document.getElementById('deact-btn');
    var confirmModal = document.getElementById('confirm-modal');
    var confirmYes = document.getElementById('confirm-yes');
    var confirmNo = document.getElementById('confirm-no');

    // Initialize Foundation for modal
    if (typeof $ !== 'undefined' && $.fn.foundation) {
        $(document).foundation();
    }

    // Register card
    registerForm.addEventListener('submit', function (e) {
        e.preventDefault();

        var accountId = document.getElementById('reg-account-id').value.trim();
        var cardId = document.getElementById('reg-card-id').value.trim();
        var ecPubkey = document.getElementById('reg-ec-pubkey').value.trim();
        var rsaPubkey = document.getElementById('reg-rsa-pubkey').value.trim();

        // Validate required fields
        var error = Validate.firstError([
            Validate.required(accountId),
            Validate.required(cardId),
            Validate.hexString(ecPubkey)
        ]);
        if (error) {
            Router.showToast(error, 'warning');
            return;
        }

        // Validate optional RSA key if provided
        if (rsaPubkey) {
            var rsaCheck = Validate.hexString(rsaPubkey);
            if (!rsaCheck.valid) {
                Router.showToast('RSA public key: ' + rsaCheck.message, 'warning');
                return;
            }
        }

        var body = {
            account_id: accountId,
            card_id: cardId,
            ec_pubkey: ecPubkey,
            rsa_pubkey: rsaPubkey || undefined
        };

        var submitBtn = registerForm.querySelector('button[type="submit"]');
        API.setButtonLoading(submitBtn, true);

        API.post('/account', body)
            .then(function () {
                Router.showToast('Card registered successfully', 'success');
                registerForm.reset();
            })
            .catch(function (err) {
                Router.showToast('Error: ' + err.message, 'alert');
            })
            .then(function () {
                API.setButtonLoading(submitBtn, false);
            });
    });

    // Deactivate card — show confirmation
    deactBtn.addEventListener('click', function () {
        var accountId = document.getElementById('deact-account-id').value.trim();
        var cardId = document.getElementById('deact-card-id').value.trim();

        if (!accountId || !cardId) {
            Router.showToast('Please fill in both fields', 'warning');
            return;
        }

        document.getElementById('confirm-account').textContent = accountId;
        document.getElementById('confirm-card').textContent = cardId;

        if (typeof $ !== 'undefined' && $.fn.foundation) {
            $('#confirm-modal').foundation('open');
        } else {
            confirmModal.style.display = 'block';
            confirmModal.style.position = 'fixed';
            confirmModal.style.top = '50%';
            confirmModal.style.left = '50%';
            confirmModal.style.transform = 'translate(-50%, -50%)';
            confirmModal.style.zIndex = '1010';
            confirmModal.style.background = '#fff';
            confirmModal.style.padding = '2rem';
            confirmModal.style.border = '1px solid #ccc';
            confirmModal.style.borderRadius = '4px';
        }
    });

    confirmYes.addEventListener('click', function () {
        var accountId = document.getElementById('deact-account-id').value.trim();
        var cardId = document.getElementById('deact-card-id').value.trim();

        API.setButtonLoading(confirmYes, true);

        API.put('/account', {
            account_id: accountId,
            card_id: cardId,
            card_active: false
        })
            .then(function () {
                Router.showToast('Card deactivated', 'success');
                document.getElementById('deactivate-form').reset();
                closeModal();
            })
            .catch(function (err) {
                Router.showToast('Error: ' + err.message, 'alert');
            })
            .then(function () {
                API.setButtonLoading(confirmYes, false);
            });
    });

    confirmNo.addEventListener('click', function () {
        closeModal();
    });

    function closeModal() {
        if (typeof $ !== 'undefined' && $.fn.foundation) {
            $('#confirm-modal').foundation('close');
        } else {
            confirmModal.style.display = 'none';
        }
    }
})();
