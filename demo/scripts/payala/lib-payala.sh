#!/usr/bin/env bash
# Payala helpers for the relay scripts in demo/scripts/payala. Sourced AFTER scripts/lib.sh, never
# executed:   . "$(dirname "$0")/../lib.sh"; . "$(dirname "$0")/lib-payala.sh"      (bash 3.2 compatible)
#
# The Payala side of the demo is the in-repo stub (demo/payala-stub, compose service payala-stub): the
# proprietary Payala API is not part of the demo. Everything below speaks the stub's HTTP API (no SQL,
# no auth; payala-stub/README.md is the contract).
#
# Relay state, shared by both relays (state/relay, gitignored; scripts/reset.sh removes it):
#   reflected/<stellar_hash>.json     forward relay record, or the reverse relay's "originated in Payala" marker
#   reflected/<stellar_hash>.pending  the forward relay's claim on a device_id, dropped before it orders
#   payala/<payala_tx_id>.json        reverse relay record (reflected, or skipped with a reason)
#   cursor / payala-cursor            high-water marks (bridge event id / Payala created_at)
#   lock / payala-lock                pid locks (one relay per direction at a time)
#   accounts.tsv                      custodial account map: stellar G <tab> payala id
#   tokens/<payala id>.jwt            cached temporal bearer tokens (0600, reused for 40 min of their 1 h life):
#                                     every host lane is ONE TCP peer for the bridge's pre-auth budget (30 /token
#                                     calls per 60 s), and the relays would otherwise log in a dozen times per run
[ -n "${DEMO_DIR:-}" ] || { printf 'lib-payala.sh: source scripts/lib.sh first\n' >&2; return 1 2>/dev/null || exit 1; }
RELAY_DIR="$STATE_DIR/relay"

# require_payala: the stub must answer (scripts/up.sh starts it with the stack)
require_payala() {
  curl -fsS -o /dev/null "$PAYALA_URL/" 2>/dev/null || die "the Payala stub is not answering at $PAYALA_URL: scripts/up.sh starts it (compose service payala-stub; scripts/logs.sh payala-stub)"
}

# payala_role_for_id <uuid> -> mint|admin|agent|beneficiary|sync|holder (the six seeded demo users; exit 1 otherwise)
payala_role_for_id() {
  [ -n "${1:-}" ] || return 1
  case "$1" in
    "${PAYALA_MINT_ID:-}") echo mint ;;
    "${PAYALA_ADMIN_ID:-}") echo admin ;;
    "${PAYALA_AGENT_ID:-}") echo agent ;;
    "${PAYALA_BENEFICIARY_ID:-}") echo beneficiary ;;
    "${PAYALA_SYNC_ID:-}") echo sync ;;
    "${DEMO_HOLDER_ID:-}") echo holder ;;
    *) return 1 ;;
  esac
}
# payala_pub_hex <role> -> that role's P-256 public key, 128 hex (state/keys/<role>.pub.hex, written by scripts/prepare.sh;
# the same key is seeded as the role's card signing key on the stub)
payala_pub_hex() { cat "$STATE_DIR/keys/$1.pub.hex"; }

# payala_users_json -> the /users collection (no Authorization header: the stub has none and journals any header sent)
payala_users_json() { curl -fsS "$PAYALA_URL/users"; }
# payala_balance <uuid> -> balance in cents
payala_balance() { curl -fsS "$PAYALA_URL/users/$1" | jq -r '.balance'; }
# payala_transfers [query] -> GET /transfers?<query>  (since, overlap, device_id, hash, sender_id, recipient_id, limit)
payala_transfers() { curl -fsS "$PAYALA_URL/transfers${1:+?$1}"; }
# payala_transfer_count [query] -> how many transfers match
payala_transfer_count() { payala_transfers "${1:-}" | jq '.Data|length'; }
# payala_journal [query] -> the stub's request journal, GET /__stub/requests?<query> (since_seq, path, method)
payala_journal() { curl -fsS "$PAYALA_URL/__stub/requests${1:+?$1}"; }
# payala_journal_seq -> the journal's current sequence number (snapshot it, then ask for since_seq=<it>)
payala_journal_seq() { curl -fsS "$PAYALA_URL/__stub/state" | jq -r '.journal_seq'; }

# ---------------------------------------------------------------- bearer tokens (cached per principal; see the header)
# relay_token <payala_id> <password> -> a temporal token: the cached one when younger than 40 min, else a fresh login
relay_token() {
  local f="$RELAY_DIR/tokens/$1.jwt" tok
  if [ -f "$f" ] && [ -n "$(find "$f" -mmin -40 2>/dev/null)" ]; then cat "$f"; return 0; fi
  tok="$(bridge_login "$1" "$2")" || return 1
  ( umask 077; mkdir -p "$RELAY_DIR/tokens" && printf '%s' "$tok" > "$f.tmp" && mv "$f.tmp" "$f" )
  printf '%s' "$tok"
}
relay_admin_jwt() { relay_token "$PAYALA_ADMIN_ID" "$IMPALA_ADMIN_PASSWORD"; }
# relay_token_invalidate <payala_id>: drop the cached token (after a 401: revoked, expired, or a new stack)
relay_token_invalidate() { rm -f "$RELAY_DIR/tokens/$1.jwt"; }
# relay_drop_on_401 <payala_id>: after a bridge_api call, forget the token when the bridge answered 401
relay_drop_on_401() { [ "$(http_code)" = "401" ] && relay_token_invalidate "$1"; return 0; }

# ---------------------------------------------------------------- account mapping / sync-back (shared by both relays)
# impala_password_for_id <payala_id> -> the bridge password of that custodial demo user ('' when it is not one)
impala_password_for_id() {
  [ -n "${1:-}" ] || return 0
  case "$1" in
    "${PAYALA_AGENT_ID:-}") printf '%s' "${IMPALA_AGENT_PASSWORD:-}" ;;
    "${PAYALA_BENEFICIARY_ID:-}") printf '%s' "${IMPALA_BENEFICIARY_PASSWORD:-}" ;;
    "${DEMO_HOLDER_ID:-}") printf '%s' "${IMPALA_HOLDER_PASSWORD:-}" ;;
    *) printf '' ;;
  esac
}
# custody_accounts_map <admin_jwt>: refresh state/relay/accounts.tsv (stellar G <tab> payala id) from the bridge
custody_accounts_map() {
  local accounts
  mkdir -p "$RELAY_DIR"
  accounts="$(bridge_api GET '/admin/custody/accounts?per_page=100' "$1")" || return 1
  if [ "$(http_code)" != "200" ]; then relay_drop_on_401 "$PAYALA_ADMIN_ID"; warn "GET /admin/custody/accounts failed ($(http_code)); account map not refreshed"; return 1; fi
  printf '%s' "$accounts" | jq -r '.data[] | [.stellar_account_id, .payala_account_id] | @tsv' > "$RELAY_DIR/accounts.tsv.tmp" \
    && mv "$RELAY_DIR/accounts.tsv.tmp" "$RELAY_DIR/accounts.tsv"
}
payala_id_for_g() { [ -f "$RELAY_DIR/accounts.tsv" ] || return 0; awk -F'\t' -v g="$1" '$1==g {print $2; exit}' "$RELAY_DIR/accounts.tsv"; }
g_for_payala_id() { [ -f "$RELAY_DIR/accounts.tsv" ] || return 0; awk -F'\t' -v id="$1" '$2==id {print $1; exit}' "$RELAY_DIR/accounts.tsv"; }

# bridge_sync_payala <payala_id> <payala_tx_id_hex64> <signed_cents> <stellar_hash> [currency]
# POST /sync/payala as the owner so the bridge mirrors the Payala transfer (memo "stellar:<hash>" links it to the payment).
bridge_sync_payala() {
  local pw tok body resp
  pw="$(impala_password_for_id "$1")"
  [ -n "$pw" ] || { warn "sync/payala: $1 is not a custodial demo user; skipped"; return 0; }
  tok="$(relay_token "$1" "$pw")" || { warn "sync/payala: bridge login failed for $1; skipped (the relay's next run mirrors nothing for this transfer: re-run with the same ids is idempotent on the bridge)"; return 0; }
  body="$(jq -cn --arg id "$1" --arg tx "$2" --argjson amt "$3" --arg memo "stellar:$4" --arg cur "${5:-USD}" '{account_id:$id,transactions:[{payala_tx_id:$tx,amount:$amt,currency:$cur,memo:$memo}]}')"
  resp="$(bridge_api POST /sync/payala "$tok" "$body")" || true
  if [ "$(http_code)" = "401" ]; then   # a cached token the bridge no longer accepts: one fresh login, one retry (the batch is idempotent per payala_tx_id)
    relay_token_invalidate "$1"
    tok="$(relay_token "$1" "$pw")" || { warn "sync/payala: bridge login failed for $1; skipped"; return 0; }
    resp="$(bridge_api POST /sync/payala "$tok" "$body")" || true
  fi
  [ "$(http_code)" = "200" ] || { warn "sync/payala for $1 returned $(http_code): $resp"; return 0; }
  log "    sync-back $1: $(printf '%s' "$resp" | jq -c '{sync_mode,applied,duplicates,conflicting,net_deltas}')"
}
