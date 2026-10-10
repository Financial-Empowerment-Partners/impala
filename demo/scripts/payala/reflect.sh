#!/usr/bin/env bash
# The forward relay: reflect settled custodial Stellar payments from the impala-bridge into the Payala stub
# (demo/payala-stub; the same requests a real Payala API would receive).
#   bridge event feed (custodial.payment_settled, origin sign, XLM) -> intent (sender, destination, hash, amount)
#   -> Payala POST /transfers/order (sender -> recipient through the custodial account map,
#      cents = stroops * DEMO_CENTS_PER_XLM / 10^7, device_id = the first 12 bytes of the Stellar tx hash)
#   -> optional --sync-back: POST /sync/payala as each owner so the bridge mirrors the Payala transfer.
# The bridge cannot push (its webhook egress guard blocks private addresses), so this polls.
# Loop guard: payments that scripts/payala/reflect-payala.sh signed for a Payala transfer carry idempotency key /
# memo "payala:…"; they are recorded (direction payala_to_impala) and never ordered back into Payala.
# Usage: scripts/payala/reflect.sh [--once|--follow] [--sync-back] [--since <event id>]
set -euo pipefail
. "$(dirname "$0")/../lib.sh"
. "$(dirname "$0")/lib-payala.sh"
load_env
require_cmd curl jq openssl od
require_payala
require_env IMPALA_ADMIN_PASSWORD PAYALA_ADMIN_ID DEMO_CENTS_PER_XLM
MODE=once; SYNC_BACK=0; SINCE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --once) MODE=once ;; --follow) MODE=follow ;; --sync-back) SYNC_BACK=1 ;;
    --since) SINCE="${2:-}"; shift ;;
    *) die "unknown option $1" ;;
  esac
  shift
done
mkdir -p "$RELAY_DIR/reflected"
CURSOR_FILE="$RELAY_DIR/cursor"
[ -n "$SINCE" ] || SINCE="$(cat "$CURSOR_FILE" 2>/dev/null || true)"
[ -n "$SINCE" ] || SINCE=0
printf '%s' "$SINCE" | grep -Eq '^[0-9]+$' || die "--since must be a bridge event id (got '$SINCE')"
LOCK="$RELAY_DIR/lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  opid="$(cat "$LOCK/pid" 2>/dev/null || echo)"
  if [ -n "$opid" ] && kill -0 "$opid" 2>/dev/null; then
    if [ "$MODE" = once ]; then log "  a relay is already running (pid $opid); it will pick up new payments"; exit 0; fi
    die "another reflect.sh is running (pid $opid)"
  fi
  warn "removing stale relay lock"; rm -rf "$LOCK"; mkdir "$LOCK"
fi
printf '%s' "$$" > "$LOCK/pid"
trap 'rm -rf "$LOCK"; cleanup_tmp' EXIT

ADMIN_JWT="$(relay_admin_jwt)"; JWT_AT="$(now_s)"
refresh_token() { if [ $(( $(now_s) - JWT_AT )) -gt 2400 ]; then ADMIN_JWT="$(relay_admin_jwt)"; JWT_AT="$(now_s)"; fi; }

reflect_one() { # <event json>
  local ev id intent_id intent sender dest hash amount_minor recipient cents device_hex cnt resp payala_tx_id rec ikey imemo marker
  ev="$1"; id="$(printf '%s' "$ev" | jq -r .id)"; intent_id="$(printf '%s' "$ev" | jq -r .payload.intent_id)"
  intent="$(bridge_api GET "/admin/custody/intents/$intent_id" "$ADMIN_JWT")"
  [ "$(http_code)" = "200" ] || { relay_drop_on_401 "$PAYALA_ADMIN_ID"; warn "event $id: intent $intent_id not readable ($(http_code)); will retry next run"; return 1; }
  sender="$(printf '%s' "$intent" | jq -r .payala_account_id)"; dest="$(printf '%s' "$intent" | jq -r .destination)"
  hash="$(printf '%s' "$intent" | jq -r .stellar_hash)"; amount_minor="$(printf '%s' "$intent" | jq -r .amount_minor)"
  [ "${#hash}" -eq 64 ] || { warn "event $id: no stellar_hash yet on intent $intent_id"; return 0; }
  if [ -f "$RELAY_DIR/reflected/$hash.json" ]; then
    if [ "$(jq -r '.direction // ""' "$RELAY_DIR/reflected/$hash.json")" = payala_to_impala ]; then
      log "  event $id: $hash originated in Payala (recorded by scripts/payala/reflect-payala.sh); not ordered back into Payala"
    else
      log "  event $id: $hash already reflected"
    fi
    return 0
  fi
  # Loop guard: a payment scripts/payala/reflect-payala.sh signed for a Payala transfer must not become a second Payala transfer.
  ikey="$(printf '%s' "$intent" | jq -r '.idempotency_key // ""')"; imemo="$(printf '%s' "$intent" | jq -r '.memo // ""')"
  if [[ "$ikey" == payala:* || "$imemo" == payala:* ]]; then
    log "  event $id: $hash originated in Payala (${ikey:-$imemo}); not ordered back into Payala"
    marker="$RELAY_DIR/reflected/$hash.json"
    jq -cn --argjson ev "$id" --arg intent "$intent_id" --arg btxid "$(printf '%s' "$ev" | jq -r .payload.btxid)" --arg h "$hash" --arg k "$ikey" --arg m "$imemo" --arg at "$(utc_now)" \
      '{event_id:$ev,intent_id:$intent,btxid:$btxid,stellar_hash:$h,direction:"payala_to_impala",idempotency_key:$k,memo:$m,skipped:true,reason:"originated in Payala",recorded_at:$at}' \
      > "$marker.tmp" && mv "$marker.tmp" "$marker"
    return 0
  fi
  recipient="$(payala_id_for_g "$dest")"
  if [ -z "$recipient" ]; then custody_accounts_map "$ADMIN_JWT"; recipient="$(payala_id_for_g "$dest")"; fi
  if [ -z "$recipient" ]; then warn "event $id: destination $dest is not a mapped custodial account; skipped"; return 0; fi
  payala_role_for_id "$sender" >/dev/null || { warn "event $id: sender $sender is not a Payala demo user; skipped"; return 0; }
  if [ "$recipient" = "$sender" ]; then
    # a payment to the sender's own address moves nothing between Payala users; the stub refuses a self-order (400), so record and move on
    log "  event $id: $hash is a self-payment of $sender; nothing to order in Payala"
    jq -cn --argjson ev "$id" --arg intent "$intent_id" --arg h "$hash" --arg s "$sender" --arg at "$(utc_now)" \
      '{event_id:$ev,intent_id:$intent,stellar_hash:$h,direction:"impala_to_payala",sender:$s,recipient:$s,skipped:true,reason:"self-payment",recorded_at:$at}' \
      > "$RELAY_DIR/reflected/$hash.json.tmp" && mv "$RELAY_DIR/reflected/$hash.json.tmp" "$RELAY_DIR/reflected/$hash.json"
    return 0
  fi
  if [ $(( amount_minor * DEMO_CENTS_PER_XLM % 10000000 )) -ne 0 ]; then warn "event $id: $amount_minor stroops is not a whole number of cents; skipped"; return 0; fi
  cents=$(( amount_minor * DEMO_CENTS_PER_XLM / 10000000 ))
  device_hex="${hash:0:24}"
  # Claim the device_id before ordering so a concurrent scripts/payala/reflect-payala.sh recognises the transfer as ours.
  : > "$RELAY_DIR/reflected/$hash.pending"
  # Payala-side idempotency: the ledger keys nothing on our data, so look the device_id up first
  cnt="$(payala_transfer_count "device_id=$device_hex")" \
    || { warn "event $id: GET /transfers failed; will retry next run"; return 1; }
  case "$cnt" in 0|[1-9]*) ;; *) warn "event $id: unexpected answer '$cnt' from GET /transfers; will retry next run"; return 1 ;; esac
  if [ "$cnt" != "0" ]; then
    log "  event $id: Payala already has a transfer with device_id $device_hex; recording as reflected"
    payala_tx_id="$(payala_transfers "device_id=$device_hex" | jq -r '.Data[0].hash_hex')" \
      || { warn "event $id: GET /transfers failed; will retry next run"; return 1; }
    [ "${#payala_tx_id}" -eq 64 ] || { warn "event $id: could not read the Payala tx id; will retry next run"; return 1; }
  else
    info "event $id: reflecting $hash ($amount_minor stroops -> $cents cents) $sender -> $recipient"
    resp="$("$DEMO_DIR/scripts/payala/payala-order.sh" "$sender" "$recipient" "$cents" "$device_hex")" || { warn "event $id: Payala order failed; will retry next run"; return 1; }
    payala_tx_id="$(printf '%s' "$resp" | jq -r .hash | b64_to_hex)"
  fi
  rec="$(jq -cn --argjson ev "$id" --arg intent "$intent_id" --arg btxid "$(printf '%s' "$ev" | jq -r .payload.btxid)" --arg s "$sender" --arg r "$recipient" --argjson cents "$cents" --arg dev "$device_hex" --arg ptx "$payala_tx_id" --arg h "$hash" --arg at "$(utc_now)" --arg hu "$(horizon_tx_url "$hash")" --arg eu "$(explorer_tx_url "$hash")" \
        '{event_id:$ev,intent_id:$intent,btxid:$btxid,stellar_hash:$h,direction:"impala_to_payala",sender:$s,recipient:$r,cents:$cents,device_id_hex:$dev,payala_tx_id:$ptx,horizon_url:$hu,explorer_url:$eu,reflected_at:$at}')"
  printf '%s\n' "$rec" > "$RELAY_DIR/reflected/$hash.json.tmp" && mv "$RELAY_DIR/reflected/$hash.json.tmp" "$RELAY_DIR/reflected/$hash.json"
  rm -f "$RELAY_DIR/reflected/$hash.pending"
  txid_recorded "$hash" || emit_txid impala_to_payala "$hash" "payala_tx_id=$payala_tx_id $cents cents"
  ok "reflected: payala_tx_id=$payala_tx_id ($cents cents)"
  if [ "$SYNC_BACK" = 1 ]; then
    bridge_sync_payala "$sender" "$payala_tx_id" "$(( -cents ))" "$hash"
    bridge_sync_payala "$recipient" "$payala_tx_id" "$cents" "$hash"
  fi
  return 0
}

custody_accounts_map "$ADMIN_JWT"
n=0
while :; do
  refresh_token
  from=$(( SINCE > 20 ? SINCE - 20 : 0 ))   # small overlap: outbox ids become visible out of order under concurrency
  page="$(bridge_api GET "/admin/events?since=$from&limit=200" "$ADMIN_JWT")"
  [ "$(http_code)" = "200" ] || { relay_drop_on_401 "$PAYALA_ADMIN_ID"; die "GET /admin/events failed ($(http_code)): $page"; }
  n=0; failed=0; maxid="$SINCE"
  # one settled-payment event per line, base64-wrapped so the JSON survives word splitting
  events_b64="$(printf '%s' "$page" | jq -r '.events[] | select(.event_type=="custodial.payment_settled" and .payload.origin=="sign" and .payload.asset_code=="XLM") | tojson | @base64')"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    ev="$(printf '%s' "$line" | openssl base64 -d -A)"
    n=$((n + 1))
    # </dev/null: commands inside (curl) must not eat the remaining event lines
    reflect_one "$ev" </dev/null || failed=$((failed + 1))
  done <<EOT
$events_b64
EOT
  m="$(printf '%s' "$page" | jq -r '[.events[].id] | max // empty')"
  if [ -n "$m" ] && [ "$m" -gt "$maxid" ]; then maxid="$m"; fi
  if [ "$failed" -eq 0 ]; then
    printf '%s\n' "$maxid" > "$CURSOR_FILE.tmp" && mv "$CURSOR_FILE.tmp" "$CURSOR_FILE"; SINCE="$maxid"
  else
    warn "$failed event(s) failed; cursor not advanced past $SINCE"
  fi
  [ "$MODE" = follow ] || break
  sleep 5
done
if [ "$n" -gt 0 ]; then ok "processed $n settled payment event(s); cursor=$SINCE"; else log "  no new settled payments (cursor=$SINCE)"; fi
