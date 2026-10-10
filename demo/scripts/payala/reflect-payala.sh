#!/usr/bin/env bash
# The reverse relay: reflect Payala transfers into the impala-bridge.
#   the Payala stub's ledger (GET /transfers?since=<cursor>&overlap=60, polled)
#   -> for an Order between two custodial demo users: POST /managed-account/sign as the sender
#      (the bridge holds the seed), amount = cents / DEMO_CENTS_PER_XLM, memo "payala:<payala_tx_id[0:20]>",
#      idempotency_key "payala:<payala_tx_id[0:56]>" (the bridge replays the recorded outcome for a repeated key,
#      so re-running never pays twice)
#   -> Horizon confirmation; the testnet transaction id is emitted (state/testnet-txids.tsv)
#   -> optional --sync-back: POST /sync/payala as the sender (-cents) and the recipient (+cents), memo "stellar:<hash>",
#      so the bridge mirrors the Payala transfer next to its own custodial_sign row.
# Loop guard: transfers that scripts/payala/reflect.sh created from Stellar payments (device_id = hash prefix) are
# recognised and skipped here, and scripts/payala/reflect.sh skips the payments this relay signs (idempotency key /
# memo prefix "payala:").
# Usage: scripts/payala/reflect-payala.sh [--once|--follow] [--sync-back] [--since <YYYY-MM-DDTHH:MM:SS[.ffffff]Z>]
set -euo pipefail
. "$(dirname "$0")/../lib.sh"
. "$(dirname "$0")/lib-payala.sh"
load_env
require_cmd curl jq
require_payala
require_env IMPALA_ADMIN_PASSWORD PAYALA_ADMIN_ID PAYALA_AGENT_ID PAYALA_BENEFICIARY_ID DEMO_CENTS_PER_XLM
MODE=once; SYNC_BACK=0; SINCE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --once) MODE=once ;; --follow) MODE=follow ;; --sync-back) SYNC_BACK=1 ;;
    --since) SINCE="${2:-}"; shift ;;
    *) die "unknown option $1" ;;
  esac
  shift
done
REC_DIR="$RELAY_DIR/payala"; mkdir -p "$REC_DIR" "$RELAY_DIR/reflected"
CURSOR_FILE="$RELAY_DIR/payala-cursor"
[ -n "$SINCE" ] || SINCE="$(cat "$CURSOR_FILE" 2>/dev/null || true)"
[ -n "$SINCE" ] || SINCE=1970-01-01T00:00:00Z
printf '%s' "$SINCE" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$' || die "--since must look like 2026-09-28T12:00:00Z (got '$SINCE')"
LOCK="$RELAY_DIR/payala-lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  opid="$(cat "$LOCK/pid" 2>/dev/null || echo)"
  if [ -n "$opid" ] && kill -0 "$opid" 2>/dev/null; then
    if [ "$MODE" = once ]; then log "  a payala relay is already running (pid $opid); it will pick up new transfers"; exit 0; fi
    die "another reflect-payala.sh is running (pid $opid)"
  fi
  warn "removing stale payala relay lock"; rm -rf "$LOCK"; mkdir "$LOCK"
fi
printf '%s' "$$" > "$LOCK/pid"
trap 'rm -rf "$LOCK"; cleanup_tmp' EXIT
TAB="$(printf '\t')"

ADMIN_JWT="$(relay_admin_jwt)"; JWT_AT="$(now_s)"
refresh_token() { if [ $(( $(now_s) - JWT_AT )) -gt 2400 ]; then ADMIN_JWT="$(relay_admin_jwt)"; JWT_AT="$(now_s)"; fi; }

record() { printf '%s\n' "$2" > "$REC_DIR/$1.json.tmp" && mv "$REC_DIR/$1.json.tmp" "$REC_DIR/$1.json"; } # <ptx> <json>
skip_record() { # <ptx> <base json> <reason>
  log "  transfer ${1:0:12}…: $3; skipped"
  record "$1" "$(printf '%s' "$2" | jq -c --arg r "$3" --arg at "$(utc_now)" '. + {skipped:true, reason:$r, recorded_at:$at}')"
}
bridge_msg() { printf '%s' "$1" | jq -r '.message // .error.message // .' 2>/dev/null | head -c 200; }

reflect_one() { # <ptx> <sender> <recipient> <cents> <currency> <device_hex> <created_at> <kind>
  local ptx="$1" sender="$2" recipient="$3" cents="$4" currency="$5" device_hex="$6" created="$7" kind="$8"
  local base sender_g recipient_g pw txs stroops xlm memo ikey tok body resp hash btxid intent replayed i tx ledger marker rec
  base="$(jq -cn --arg p "$ptx" --arg k "$kind" --arg s "$sender" --arg r "$recipient" --argjson c "$cents" --arg cur "$currency" --arg d "$device_hex" --arg at "$created" \
    '{payala_tx_id:$p,kind:$k,sender:$s,recipient:$r,cents:$c,currency:$cur,device_id_hex:$d,created_at:$at,direction:"payala_to_impala"}')"
  sender_g="$(g_for_payala_id "$sender")"; recipient_g="$(g_for_payala_id "$recipient")"
  if [ -z "$sender_g" ] || [ -z "$recipient_g" ]; then
    custody_accounts_map "$ADMIN_JWT"; sender_g="$(g_for_payala_id "$sender")"; recipient_g="$(g_for_payala_id "$recipient")"
  fi
  if [ -z "$sender_g" ] || [ -z "$recipient_g" ]; then skip_record "$ptx" "$base" "$sender -> $recipient is not between two custodial bridge accounts"; return 0; fi
  pw="$(impala_password_for_id "$sender")"
  [ -n "$pw" ] || { skip_record "$ptx" "$base" "no bridge password for sender $sender"; return 0; }
  # A reflection made by scripts/payala/reflect.sh carries the Stellar hash prefix as device_id: never pay it again.
  if ls "$RELAY_DIR/reflected/$device_hex"* >/dev/null 2>&1; then skip_record "$ptx" "$base" "originated on Stellar (reflected by scripts/payala/reflect.sh)"; return 0; fi
  txs="$(bridge_api GET "/transactions?q=$device_hex&per_page=5" "$ADMIN_JWT")"
  [ "$(http_code)" = "200" ] || { relay_drop_on_401 "$PAYALA_ADMIN_ID"; warn "transfer ${ptx:0:12}…: bridge GET /transactions failed ($(http_code)); will retry next run"; return 1; }
  if printf '%s' "$txs" | jq -e '[.data[]|select(.origin=="custodial_sign")]|length>0' >/dev/null; then
    skip_record "$ptx" "$base" "originated on Stellar (bridge has a custodial_sign row with this hash prefix)"; return 0
  fi
  # Already mirrored in the bridge (relay state lost)? Then it was reflected before, in one direction or the other.
  txs="$(bridge_api GET "/transactions?q=$ptx&per_page=5" "$ADMIN_JWT")"
  [ "$(http_code)" = "200" ] || { warn "transfer ${ptx:0:12}…: bridge GET /transactions failed ($(http_code)); will retry next run"; return 1; }
  if printf '%s' "$txs" | jq -e '[.data[]|select(.origin=="payala_sync")]|length>0' >/dev/null; then
    skip_record "$ptx" "$base" "already mirrored in the bridge (payala_sync rows exist)"; return 0
  fi
  stroops="$(cents_to_stroops "$cents")" || { skip_record "$ptx" "$base" "$cents cents is not a whole number of stroops at $DEMO_CENTS_PER_XLM cents/XLM"; return 0; }
  xlm="$(stroops_to_xlm "$stroops")"
  memo="payala:${ptx:0:20}"; ikey="payala:${ptx:0:56}"
  info "transfer ${ptx:0:12}…: reflecting $cents $currency ($xlm XLM) $sender -> $recipient via POST /managed-account/sign"
  tok="$(relay_token "$sender" "$pw")" || { warn "transfer ${ptx:0:12}…: bridge login failed for $sender; will retry next run"; return 1; }
  body="$(jq -cn --arg id "$sender" --arg d "$recipient_g" --arg a "$xlm" --arg m "$memo" --arg k "$ikey" '{payala_account_id:$id,destination:$d,amount:$a,memo:$m,idempotency_key:$k}')"
  resp="$(bridge_api POST /managed-account/sign "$tok" "$body")" || true
  case "$(http_code)" in
    200) ;;
    202) warn "bridge answered 202 ($(printf '%s' "$resp" | jq -r .status)); polling the intent (same idempotency key, never resending)"
         i=0; until printf '%s' "$resp" | jq -e '.status=="settled"' >/dev/null; do
           if printf '%s' "$resp" | jq -e '.status=="rejected"' >/dev/null; then skip_record "$ptx" "$base" "bridge rejected the payment: $(bridge_msg "$resp")"; return 0; fi
           i=$((i + 1)); [ "$i" -le 30 ] || { warn "transfer ${ptx:0:12}…: still not settled; will retry next run"; return 1; }; sleep 3
           resp="$(bridge_api GET "/managed-account/intents?payala_account_id=$sender&idempotency_key=$ikey" "$tok" | jq -c '.data[0] // {}')"
         done ;;
    401) relay_token_invalidate "$sender"; warn "transfer ${ptx:0:12}…: the bridge rejected the sender's token (401); cache dropped, will retry next run with a fresh login"; return 1 ;;
    429|5*|000) warn "transfer ${ptx:0:12}…: bridge sign not available ($(http_code)): $(bridge_msg "$resp"); will retry next run"; return 1 ;;
    *) skip_record "$ptx" "$base" "bridge refused the payment (HTTP $(http_code)): $(bridge_msg "$resp")"; return 0 ;;
  esac
  hash="$(printf '%s' "$resp" | jq -r '.stellar_hash // ""')"; btxid="$(printf '%s' "$resp" | jq -r '.btxid // ""')"
  intent="$(printf '%s' "$resp" | jq -r '.intent_id // ""')"; replayed="$(printf '%s' "$resp" | jq -r '.replayed // false')"
  [ "${#hash}" -eq 64 ] || { warn "transfer ${ptx:0:12}…: no stellar_hash in the bridge answer; will retry next run: $resp"; return 1; }
  [ "$replayed" = true ] && log "  bridge replayed the recorded outcome for idempotency key $ikey (no second payment)"
  tx="$(horizon_wait_tx "$hash" 20)" || { warn "tx $hash not on Horizon yet; will retry next run"; return 1; }
  printf '%s' "$tx" | jq -e '.successful==true' >/dev/null || { skip_record "$ptx" "$base" "Horizon reports $hash as failed"; return 0; }
  ledger="$(printf '%s' "$tx" | jq -r .ledger)"
  emit_txid payala_to_impala "$hash" "payala_tx_id=$ptx $xlm XLM ${sender_g:0:8}… -> ${recipient_g:0:8}… ledger $ledger"
  # Marker for scripts/payala/reflect.sh: this settled custodial payment must never be ordered back into Payala.
  marker="$RELAY_DIR/reflected/$hash.json"
  if [ ! -f "$marker" ]; then
    jq -cn --arg h "$hash" --arg p "$ptx" --arg i "$intent" --arg b "$btxid" --arg k "$ikey" --arg at "$(utc_now)" \
      '{stellar_hash:$h,direction:"payala_to_impala",payala_tx_id:$p,intent_id:$i,btxid:$b,idempotency_key:$k,skipped:true,reason:"originated in Payala",recorded_at:$at}' > "$marker.tmp" && mv "$marker.tmp" "$marker"
  fi
  rec="$(printf '%s' "$base" | jq -c --arg h "$hash" --arg b "$btxid" --arg i "$intent" --arg m "$memo" --arg k "$ikey" --arg x "$xlm" --argjson st "$stroops" --argjson l "$ledger" --argjson rp "$replayed" --arg at "$(utc_now)" --arg hu "$(horizon_tx_url "$hash")" --arg eu "$(explorer_tx_url "$hash")" \
    '. + {stellar_hash:$h,btxid:$b,intent_id:$i,memo:$m,idempotency_key:$k,amount_xlm:$x,stroops:$st,ledger:$l,replayed:$rp,horizon_url:$hu,explorer_url:$eu,reflected_at:$at}')"
  record "$ptx" "$rec"
  ok "reflected: stellar_hash=$hash ($xlm XLM, ledger $ledger)"
  if [ "$SYNC_BACK" = 1 ]; then
    bridge_sync_payala "$sender" "$ptx" "$(( -cents ))" "$hash" "$currency"
    bridge_sync_payala "$recipient" "$ptx" "$cents" "$hash" "$currency"
  fi
  return 0
}

custody_accounts_map "$ADMIN_JWT"
n=0
while :; do
  refresh_token
  rows="$(payala_transfers "since=$SINCE&overlap=60" | jq -r '.Data[] | [.hash_hex, .sender_id, .recipient_id, (.amount|tostring), .currency, .device_id_hex, .created_at, .kind] | @tsv')" \
    || die "GET /transfers failed"
  n=0; failed=0; maxts="$SINCE"
  # 60 s overlap (created_at is client-supplied); the record files dedupe re-read rows
  while IFS="$TAB" read -r ptx sender recipient cents currency device_hex created kind; do
    [ -n "$ptx" ] || continue
    if [ -f "$REC_DIR/$ptx.json" ]; then [[ "$created" > "$maxts" ]] && maxts="$created"; continue; fi
    n=$((n + 1))
    # </dev/null: commands inside (curl) must not eat the remaining rows
    if reflect_one "$ptx" "$sender" "$recipient" "$cents" "$currency" "$device_hex" "$created" "$kind" </dev/null; then
      [[ "$created" > "$maxts" ]] && maxts="$created"
    else
      failed=$((failed + 1))
    fi
  done <<EOT
$rows
EOT
  if [ "$failed" -eq 0 ]; then
    printf '%s\n' "$maxts" > "$CURSOR_FILE.tmp" && mv "$CURSOR_FILE.tmp" "$CURSOR_FILE"; SINCE="$maxts"
  else
    warn "$failed transfer(s) failed; cursor not advanced past $SINCE"
  fi
  [ "$MODE" = follow ] || break
  sleep 5
done
if [ "$n" -gt 0 ]; then ok "processed $n new Payala transfer(s); cursor=$SINCE"; else log "  no new Payala transfers (cursor=$SINCE)"; fi
