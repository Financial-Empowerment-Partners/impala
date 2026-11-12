/**
 * DOM-free logic for smartcards: the `POST /card` registration body (with
 * the optional SEP-10 Stellar-key group), the bridge refusals specific to
 * that group, and the per-account card list shown on the Accounts page
 * (`GET /admin/accounts/{account_id}/cards`).
 *
 * Contract: docs/sep10-card-keys.md section 6 ("POST /card" and 6.1).
 * Depends on Validate (validate.js loads first).
 *
 * @module CardsView
 */
var CardsView = (function () {
    'use strict';

    function trimmed(v) {
        return typeof v === 'string' ? v.trim() : '';
    }

    /**
     * Detect a binding signature pasted as the card's zero-padded 72-byte
     * slot instead of the trimmed DER the bridge expects: a DER SEQUENCE
     * (0x30, short-form length L) followed by nothing but zero bytes.
     * @param {string} hex - Lowercase hex, even length.
     * @returns {number|null} The trimmed length in hex characters, or null.
     */
    function paddedDerLength(hex) {
        if (hex.length < 4 || hex.slice(0, 2) !== '30') return null;
        var declared = parseInt(hex.slice(2, 4), 16);
        if (declared >= 0x80) return null;
        var total = (declared + 2) * 2;
        if (hex.length <= total) return null;
        return /^0+$/.test(hex.slice(total)) ? total : null;
    }

    /**
     * Validate the optional Stellar-key group: all three or none.
     * @param {{address: string, bindingSig: string, proofSig: string}} input
     * @returns {{ok: boolean, present?: boolean, error?: string,
     *            fields?: {stellar_address: string, stellar_binding_sig: string,
     *                      stellar_proof_sig: string}}}
     */
    function stellarFields(input) {
        input = input || {};
        var address = trimmed(input.address);
        var binding = trimmed(input.bindingSig);
        var proof = trimmed(input.proofSig);
        var filled = [address, binding, proof].filter(function (v) { return v !== ''; }).length;

        if (filled === 0) return { ok: true, present: false };
        if (filled !== 3) {
            return {
                ok: false,
                error: 'Stellar key: fill in all three fields (address, binding signature, ' +
                    'proof signature) or leave all three empty'
            };
        }

        var addr = Validate.stellarAccountId(address);
        if (!addr.valid) return { ok: false, error: 'Stellar address: ' + addr.message };

        if (!/^[0-9a-fA-F]+$/.test(binding)) {
            return { ok: false, error: 'Binding signature: must contain only hex characters (0-9, a-f)' };
        }
        if (binding.length < 16 || binding.length > 144) {
            return { ok: false, error: 'Binding signature: must be 16 to 144 hex characters (the DER signature)' };
        }
        if (binding.length % 2 !== 0) {
            return { ok: false, error: 'Binding signature: must have an even number of hex characters' };
        }
        binding = binding.toLowerCase();
        var trimmedLen = paddedDerLength(binding);
        if (trimmedLen !== null) {
            return {
                ok: false,
                error: 'Binding signature: this is the zero-padded 72-byte slot; send only the ' +
                    'DER signature, the first ' + trimmedLen + ' hex characters'
            };
        }

        if (!/^[0-9a-fA-F]{128}$/.test(proof)) {
            return { ok: false, error: 'Proof signature: must be exactly 128 hex characters (64 bytes)' };
        }

        return {
            ok: true,
            present: true,
            fields: {
                stellar_address: address,
                stellar_binding_sig: binding,
                stellar_proof_sig: proof.toLowerCase()
            }
        };
    }

    /**
     * Validate the registration form and build the `POST /card` body.
     * Without the Stellar group the body is exactly the pre-SEP-10 one
     * (same keys, same order, `rsa_pubkey` omitted when empty).
     * @param {Object} input - { accountId, cardId, ecPubkey, rsaPubkey,
     *                           stellarAddress, stellarBindingSig, stellarProofSig }
     * @returns {{ok: boolean, error?: string, body?: Object}}
     */
    function buildRegistration(input) {
        input = input || {};
        var accountId = trimmed(input.accountId);
        var cardId = trimmed(input.cardId);
        var ecPubkey = trimmed(input.ecPubkey);
        var rsaPubkey = trimmed(input.rsaPubkey);

        var error = Validate.firstError([
            Validate.required(accountId),
            Validate.required(cardId),
            Validate.hexString(ecPubkey)
        ]);
        if (error) return { ok: false, error: error };

        if (rsaPubkey) {
            var rsaCheck = Validate.hexString(rsaPubkey);
            if (!rsaCheck.valid) return { ok: false, error: 'RSA public key: ' + rsaCheck.message };
        }

        var stellar = stellarFields({
            address: input.stellarAddress,
            bindingSig: input.stellarBindingSig,
            proofSig: input.stellarProofSig
        });
        if (!stellar.ok) return { ok: false, error: stellar.error };

        var body = {
            account_id: accountId,
            card_id: cardId,
            ec_pubkey: ecPubkey,
            rsa_pubkey: rsaPubkey || undefined
        };
        if (stellar.present) {
            body.stellar_address = stellar.fields.stellar_address;
            body.stellar_binding_sig = stellar.fields.stellar_binding_sig;
            body.stellar_proof_sig = stellar.fields.stellar_proof_sig;
        }
        return { ok: true, body: body };
    }

    /**
     * Message for a failed registration. The two Stellar refusals get
     * specific advice; anything else shows the bridge's message.
     * @param {Error} err - From API.post (carries status and code).
     * @returns {string}
     */
    function registrationErrorMessage(err) {
        var code = err && err.code;
        var status = err && err.status;
        var message = (err && err.message) || 'Request failed';
        if (code === 'invalid_stellar_binding' ||
            (!code && status === 400 && message.indexOf('invalid_stellar_binding') !== -1)) {
            return 'The bridge could not verify the Stellar key\'s cross-signatures for this ' +
                'account and card. The binding and proof signatures must come from this card, ' +
                'personalized for this account id and card id, with this EC public key.';
        }
        if (code === 'stellar_address_in_use' ||
            (!code && status === 409 && message.indexOf('stellar_address_in_use') !== -1)) {
            return 'This Stellar address is already registered on another active card. ' +
                'Deactivate that card first, or check that the values were read from this card.';
        }
        return 'Error: ' + message;
    }

    /**
     * Normalise `GET /admin/accounts/{account_id}/cards`.
     * @param {*} payload - `{"cards": [card...]}`
     * @returns {{cards: Array<Object>, malformed: boolean}}
     */
    function normalizeCardList(payload) {
        var list = payload && typeof payload === 'object' && Array.isArray(payload.cards)
            ? payload.cards : null;
        if (!list) return { cards: [], malformed: true };
        return { cards: list.map(cardRow), malformed: false };
    }

    function str(v) {
        return typeof v === 'string' && v !== '' ? v : null;
    }

    /**
     * Display model for one card. `sep10` is true only for a well-formed
     * account address (the card can sign in with SEP-10).
     * @param {*} card
     * @returns {Object}
     */
    function cardRow(card) {
        card = card && typeof card === 'object' ? card : {};
        var status;
        if (card.active === true) status = { label: 'active', cls: 'ok' };
        else if (card.active === false) status = { label: 'deleted', cls: 'neutral' };
        else status = { label: 'unknown', cls: 'neutral' };
        var address = str(card.stellar_address);
        return {
            cardId: str(card.card_id),
            status: status,
            createdAt: str(card.created_at),
            deletedAt: str(card.deleted_at),
            stellarAddress: address,
            sep10: address !== null && Validate.stellarAccountId(address).valid
        };
    }

    /**
     * The roles whose accounts the bridge refuses on `POST /auth/sep10`:
     * every role that holds a bridge capability (auth.rs
     * `role_is_privileged`). The tests assert this list against the shared
     * role/capability fixture, so it cannot drift from the bridge's matrix.
     * @type {string[]}
     */
    var SEP10_REFUSED_ROLES = ['admin', 'treasurer', 'key-custodian', 'auditor'];

    /**
     * Whether the bridge refuses SEP-10 sign-in for an account: it holds a
     * privileged role, or it is allowlisted (effective admin). Such an
     * account's cards sign in with the legacy card challenge instead. An
     * unknown role is not presumed refused: the note is display only.
     * @param {string} role - The account's stored role.
     * @param {boolean} allowlisted - The accounts API's `allowlisted` flag.
     * @returns {boolean}
     */
    function sep10RefusedFor(role, allowlisted) {
        if (allowlisted === true) return true;
        return typeof role === 'string' && SEP10_REFUSED_ROLES.indexOf(role) !== -1;
    }

    /**
     * How a failed card-list load renders. An older bridge has no such
     * route: its 404 is the router's, with no error envelope (no code). A
     * 404 that does carry an envelope came from the handler and is shown.
     * @param {Error} err
     * @returns {{kind: string, message: string}} kind: unsupported | forbidden | error
     */
    function classifyCardListError(err) {
        var status = err && err.status;
        if (status === 404 && !(err && err.code)) {
            return { kind: 'unsupported', message: 'This bridge does not list an account\'s cards.' };
        }
        if (status === 403) {
            return { kind: 'forbidden', message: 'Your role cannot list this account\'s cards.' };
        }
        return { kind: 'error', message: (err && err.message) || 'Could not load the cards.' };
    }

    return {
        stellarFields: stellarFields,
        buildRegistration: buildRegistration,
        registrationErrorMessage: registrationErrorMessage,
        normalizeCardList: normalizeCardList,
        cardRow: cardRow,
        SEP10_REFUSED_ROLES: SEP10_REFUSED_ROLES,
        sep10RefusedFor: sep10RefusedFor,
        classifyCardListError: classifyCardListError
    };
})();
