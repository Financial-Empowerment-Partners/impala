/**
 * Cards page module — register and deactivate hardware smartcards.
 *
 * Registration stores the card's EC public key (and optional RSA public key)
 * linked to an account, plus, optionally, the card's Stellar key for SEP-10
 * sign-in (address + two cross-signatures, all three or none; see
 * CardsView.buildRegistration). Registration is POST /card; the bridge
 * registers a card only under the signed-in account. Deactivation uses a
 * confirmation modal (Foundation JS if available, CSS fallback otherwise)
 * before sending DELETE /card.
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

        var value = function (id) { return document.getElementById(id).value; };

        // Validation and the body shape live in the DOM-free CardsView.
        // Without the optional Stellar group the body is exactly the
        // pre-SEP-10 one.
        var built = CardsView.buildRegistration({
            accountId: value('reg-account-id'),
            cardId: value('reg-card-id'),
            ecPubkey: value('reg-ec-pubkey'),
            rsaPubkey: value('reg-rsa-pubkey'),
            stellarAddress: value('reg-stellar-address'),
            stellarBindingSig: value('reg-stellar-binding'),
            stellarProofSig: value('reg-stellar-proof')
        });
        if (!built.ok) {
            Router.showToast(built.error, 'warning');
            return;
        }

        var submitBtn = registerForm.querySelector('button[type="submit"]');
        API.setButtonLoading(submitBtn, true);

        // Registration is POST /card (handlers/card.rs create_card). This
        // used to post to /account, the account-creation route, which
        // rejects a card body.
        API.post('/card', built.body)
            .then(function () {
                Router.showToast('Card registered successfully', 'success');
                registerForm.reset();
            })
            .catch(function (err) {
                Router.showToast(CardsView.registrationErrorMessage(err), 'alert');
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
        // DELETE /card scopes to the authenticated account server-side, so the
        // card id alone identifies the target.
        var cardId = document.getElementById('deact-card-id').value.trim();

        API.setButtonLoading(confirmYes, true);

        // Deactivation is DELETE /card {card_id}: the bridge soft-deletes the
        // card, scoped to the authenticated account (account_id is taken from
        // the token, not the body). The previous PUT /account with
        // card_active silently no-op'd — that field is not part of the
        // account update contract, so it returned 200 success:false and the
        // card stayed active. Honor the success envelope.
        API.del('/card', { card_id: cardId })
            .then(function (res) {
                if (res && res.success === false) {
                    Router.showToast(res.message || 'Card not found or already inactive', 'warning');
                    return;
                }
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
