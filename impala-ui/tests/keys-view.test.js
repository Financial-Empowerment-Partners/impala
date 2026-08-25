import { describe, it, expect, beforeAll } from 'vitest';
import { loadScript } from './helpers/load-script.js';

// keys-view.js holds the confirmation rules for replacing credentials that
// move money. It is DOM-free so those rules are testable directly — the
// browser layer only renders what these functions decide.
let KeysView;
beforeAll(() => {
    KeysView = loadScript('keys-view.js', 'KeysView');
});

/**
 * A credential currently supplied by the deployment's environment.
 *
 * `replace_target_fingerprint` is what the bridge computes as "the credential
 * this would supersede" — the stored row if there is one, otherwise whatever
 * is running. The client keys every decision off it rather than picking
 * between the other fingerprints itself.
 */
function envSourced(overrides) {
    return Object.assign({
        kind: 'changelly_crypto',
        parts: ['api_key', 'private_key'],
        required_parts: ['api_key', 'private_key'],
        effective_source: 'env',
        effective_fingerprint: 'aabbccddeeff0011',
        replace_target_fingerprint: 'aabbccddeeff0011',
        active: true,
        env_vars_set: ['CHANGELLY_API_KEY', 'CHANGELLY_PRIVATE_KEY'],
        confirm_phrase: 'replace changelly_crypto pubnet',
        pending_restart: false,
        in_flight_count: 0,
        history: []
    }, overrides || {});
}

/** Nothing configured for this kind at all. */
function unconfigured(overrides) {
    return Object.assign({
        kind: 'owlpay',
        parts: ['api_key', 'webhook_secret'],
        required_parts: ['api_key'],
        effective_source: 'unconfigured',
        active: false,
        env_vars_set: [],
        pending_restart: false,
        in_flight_count: 0,
        history: []
    }, overrides || {});
}

describe('isReplacement', () => {
    it('treats an environment-sourced credential as something being replaced', () => {
        // The critical case: no stored row exists, so a check that looked only
        // at the database would call this an "add" and skip every confirmation
        // — while quietly superseding the key the deployment supplies.
        expect(KeysView.isReplacement(envSourced())).toBe(true);
    });

    it('treats an unconfigured kind as an add', () => {
        expect(KeysView.isReplacement(unconfigured())).toBe(false);
    });
});

describe('buildImport', () => {
    it('adds without confirmation when nothing is in effect', () => {
        const result = KeysView.buildImport(unconfigured(), {
            parts: { api_key: 'live-key' }
        });
        expect(result.ok).toBe(true);
        expect(result.body.parts).toEqual({ api_key: 'live-key' });
        // An add must not claim to be a replacement: the flag ends up in the
        // audit event.
        expect(result.body.replace).toBeUndefined();
        expect(result.body.expected_fingerprint).toBeUndefined();
    });

    it('refuses a replacement without the typed phrase', () => {
        const result = KeysView.buildImport(envSourced(), {
            parts: { api_key: 'k', private_key: 'p' }
        });
        expect(result.ok).toBe(false);
        expect(result.error).toContain('replace changelly_crypto pubnet');
    });

    it('refuses a phrase for the wrong network', () => {
        // The commonest operator error is the right key in the wrong
        // environment, and the network in the phrase is the only place it is
        // caught.
        const result = KeysView.buildImport(envSourced(), {
            parts: { api_key: 'k', private_key: 'p' },
            confirmTyped: 'replace changelly_crypto testnet'
        });
        expect(result.ok).toBe(false);
    });

    it('sends the compare-and-swap token from the payload, not a guess', () => {
        const view = envSourced();
        const result = KeysView.buildImport(view, {
            parts: { api_key: 'k', private_key: 'p' },
            confirmTyped: view.confirm_phrase
        });
        expect(result.ok).toBe(true);
        expect(result.body.replace).toBe(true);
        expect(result.body.expected_fingerprint).toBe(view.replace_target_fingerprint);
        expect(result.body.confirm_phrase).toBe(view.confirm_phrase);
    });

    // The case that used to deadlock: a credential imported but not yet
    // activated. Nothing is RUNNING from the database, so a check that looked
    // only at the effective credential would call the next import an addition
    // — and the server, comparing against the live stored row, would reject it
    // with advice no amount of refreshing could satisfy.
    it('treats a stored-but-not-running credential as a replacement', () => {
        const view = unconfigured({
            stored_fingerprint: 'storedfp',
            stored_version: 1,
            replace_target_fingerprint: 'storedfp',
            confirm_phrase: 'replace owlpay pubnet',
            pending_restart: true
        });
        expect(KeysView.isReplacement(view)).toBe(true);

        const refused = KeysView.buildImport(view, { parts: { api_key: 'k' } });
        expect(refused.ok).toBe(false);

        const result = KeysView.buildImport(view, {
            parts: { api_key: 'k' },
            confirmTyped: 'replace owlpay pubnet'
        });
        expect(result.ok).toBe(true);
        expect(result.body.expected_fingerprint).toBe('storedfp');
    });

    it('refuses to replace when the bridge supplied no phrase', () => {
        // Rather than reconstructing the phrase locally, which would drift from
        // the server the moment either side changed.
        const view = envSourced({ confirm_phrase: undefined });
        const result = KeysView.buildImport(view, {
            parts: { api_key: 'k', private_key: 'p' },
            confirmTyped: 'replace changelly_crypto pubnet'
        });
        expect(result.ok).toBe(false);
        expect(result.error).toContain('refresh');
    });

    it('requires every required part', () => {
        const result = KeysView.buildImport(unconfigured({
            required_parts: ['api_key', 'private_key']
        }), { parts: { api_key: 'k' } });
        expect(result.ok).toBe(false);
        expect(result.error).toContain('private_key');
    });

    it('drops blank optional parts instead of sending empty strings', () => {
        // An empty webhook_secret would fail the server's own "must not be
        // empty" check; omitting it means "not configured", which is valid.
        const result = KeysView.buildImport(unconfigured(), {
            parts: { api_key: 'live-key', webhook_secret: '   ' }
        });
        expect(result.ok).toBe(true);
        expect(result.body.parts.webhook_secret).toBeUndefined();
    });

    it('trims pasted values', () => {
        const result = KeysView.buildImport(unconfigured(), {
            parts: { api_key: '  live-key\n' }
        });
        expect(result.body.parts.api_key).toBe('live-key');
    });

    it('passes the acknowledgement flags through', () => {
        const view = envSourced({ in_flight_count: 3 });
        const result = KeysView.buildImport(view, {
            parts: { api_key: 'k', private_key: 'p' },
            confirmTyped: view.confirm_phrase,
            strandInFlight: true,
            skipVerify: true,
            note: 'OPS-1421'
        });
        expect(result.body.strand_in_flight).toBe(true);
        expect(result.body.skip_verify).toBe(true);
        expect(result.body.note).toBe('OPS-1421');
    });
});

describe('buildRevoke', () => {
    const stored = () => envSourced({
        effective_source: 'db',
        stored_fingerprint: 'aabbccddeeff0011',
        stored_version: 2
    });

    it('requires the typed phrase and the fallback acknowledgement', () => {
        expect(KeysView.buildRevoke(stored(), {}).ok).toBe(false);
        expect(KeysView.buildRevoke(stored(), {
            confirmTyped: 'replace changelly_crypto pubnet'
        }).ok).toBe(false);
        expect(KeysView.buildRevoke(stored(), {
            confirmTyped: 'replace changelly_crypto pubnet',
            acknowledgedNextSource: true
        }).ok).toBe(true);
    });

    // Revoking leaves in-flight orders with nothing able to reconcile them —
    // more starkly than a replacement, since the provider may end up
    // unconfigured entirely.
    it('requires acknowledging in-flight work', () => {
        const view = envSourced({
            effective_source: 'db',
            stored_fingerprint: 'aabbccddeeff0011',
            in_flight_count: 2
        });
        const refused = KeysView.buildRevoke(view, {
            confirmTyped: 'replace changelly_crypto pubnet',
            acknowledgedNextSource: true
        });
        expect(refused.ok).toBe(false);

        const result = KeysView.buildRevoke(view, {
            confirmTyped: 'replace changelly_crypto pubnet',
            acknowledgedNextSource: true,
            strandInFlight: true
        });
        expect(result.ok).toBe(true);
        expect(result.body.strand_in_flight).toBe(true);
    });

    it('refuses when there is no stored credential to revoke', () => {
        // Revoke acts on the stored row; an environment credential is removed
        // from the deployment, not through this API.
        const result = KeysView.buildRevoke(envSourced(), {
            confirmTyped: 'replace changelly_crypto pubnet',
            acknowledgedNextSource: true
        });
        expect(result.ok).toBe(false);
    });
});

describe('buildMerge', () => {
    const stored = () => envSourced({
        effective_source: 'db',
        stored_fingerprint: 'aabbccddeeff0011',
        stored_version: 2
    });

    it('requires the typed phrase and at least one change', () => {
        expect(KeysView.buildMerge(stored(), { confirmTyped: 'replace changelly_crypto pubnet' }).ok)
            .toBe(false);
        expect(KeysView.buildMerge(stored(), { setParts: { api_key: 'new' } }).ok).toBe(false);
    });

    // A merge is always a replacement, so it carries the same acknowledgements.
    // Without them the server rejects every merge while any order is in
    // flight, and the UI has no way to say so.
    it('passes the in-flight and verification acknowledgements through', () => {
        const result = KeysView.buildMerge(stored(), {
            setParts: { api_key: 'new' },
            confirmTyped: 'replace changelly_crypto pubnet',
            strandInFlight: true,
            skipVerify: true
        });
        expect(result.ok).toBe(true);
        expect(result.body.strand_in_flight).toBe(true);
        expect(result.body.skip_verify).toBe(true);
        expect(result.body.expected_fingerprint).toBe('aabbccddeeff0011');
    });

    it('sends a dropped part as an explicit list', () => {
        const result = KeysView.buildMerge(stored(), {
            dropPart: 'webhook_secret',
            confirmTyped: 'replace changelly_crypto pubnet'
        });
        expect(result.ok).toBe(true);
        expect(result.body.drop_parts).toEqual(['webhook_secret']);
    });
});

describe('revokeFallback', () => {
    it('warns that a different environment key takes over', () => {
        // Revocation silently handing the provider back to an older key is the
        // surprise worth spelling out before it happens.
        const text = KeysView.revokeFallback(envSourced());
        expect(text).toContain('CHANGELLY_API_KEY');
        expect(text).toContain('DIFFERENT');
    });

    it('warns that the provider stops working when nothing remains', () => {
        const text = KeysView.revokeFallback(unconfigured());
        expect(text).toContain('UNCONFIGURED');
    });
});

describe('pendingNotice', () => {
    it('says nothing when what is stored is what is running', () => {
        expect(KeysView.pendingNotice(envSourced())).toBeNull();
    });

    it('explains a stored version that has not been activated yet', () => {
        const notice = KeysView.pendingNotice(envSourced({
            pending_restart: true,
            stored_fingerprint: 'ffff',
            stored_version: 4
        }));
        expect(notice.text).toContain('4');
        expect(notice.text).toContain('Roll the deployment');
    });

    it('explains a stored credential that this instance is not running at all', () => {
        const notice = KeysView.pendingNotice(unconfigured({
            pending_restart: true,
            stored_fingerprint: 'ffff'
        }));
        expect(notice.text).toContain('Stored but not running');
    });
});

describe('sourceBadge', () => {
    it('distinguishes imported, environment, and unconfigured', () => {
        expect(KeysView.sourceBadge(envSourced()).label).toBe('environment');
        expect(KeysView.sourceBadge(envSourced({ effective_source: 'db' })).label)
            .toBe('imported');
        expect(KeysView.sourceBadge(unconfigured()).label).toBe('not configured');
    });

    it('surfaces a resolution failure ahead of everything else', () => {
        // A stored credential that failed to open disables the provider; that
        // must not read as a plain "not configured".
        const badge = KeysView.sourceBadge(unconfigured({
            resolution_error: 'row 1 failed its binding check'
        }));
        expect(badge.label).toBe('failed');
        expect(badge.title).toContain('binding check');
    });
});

describe('inFlightWarning', () => {
    it('is silent when nothing is running', () => {
        expect(KeysView.inFlightWarning(envSourced())).toBeNull();
    });

    it('names the stranding risk', () => {
        const text = KeysView.inFlightWarning(envSourced({ in_flight_count: 2 }));
        expect(text).toContain('2');
        expect(text).toContain('stranded');
    });
});

describe('shortFingerprint', () => {
    it('never renders an empty value as blank', () => {
        expect(KeysView.shortFingerprint(null)).toBe('—');
        expect(KeysView.shortFingerprint('')).toBe('—');
    });

    it('elides long fingerprints', () => {
        expect(KeysView.shortFingerprint('aabbccddeeff0011')).toBe('aabbccddeeff…');
        expect(KeysView.shortFingerprint('short')).toBe('short');
    });
});
