#!/usr/bin/env bash
# List the Stellar testnet transaction ids the kit has created or seen (state/testnet-txids.tsv, or
# DEMO_TXID_FILE), with the URLs to look them up elsewhere.
# Usage: scripts/txids.sh [--check] [--json]
#   --check   ask Horizon about every hash (successful, ledger, memo) — exit 1 if any is missing or failed
#   --json    print a JSON array instead of the table
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
require_cmd curl jq
CHECK=0; JSON=0
for a in "$@"; do case "$a" in --check) CHECK=1 ;; --json) JSON=1 ;; *) die "unknown option $a" ;; esac; done
F="$(txid_log_file)"
[ -s "$F" ] || die "no testnet transaction ids recorded yet ($F); run scripts/seed.sh or a scenario first"
fails=0
if [ "$JSON" = 1 ]; then
  jq -Rn --arg horizon "$HORIZON_URL" '[inputs | select(length>0) | split("\t") | {recorded_at:.[0], kind:.[1], hash:.[2], explorer_url:.[3], note:(.[4] // ""), horizon_url:($horizon + "/transactions/" + .[2])}]' < "$F"
else
  log "testnet transaction ids ($F):"
  printf '  %-20s %-20s %-64s %s\n' recorded kind hash explorer_url >&2
  while IFS="$(printf '\t')" read -r at kind hash url note; do
    [ -n "$hash" ] || continue
    printf '  %-20s %-20s %s %s\n' "$at" "$kind" "$hash" "$url" >&2
    [ -n "$note" ] && printf '  %-20s %-20s   %s\n' "" "" "$note" >&2
  done < "$F"
fi
if [ "$CHECK" = 1 ]; then
  log ""; info "asking Horizon ($HORIZON_URL)"
  while IFS="$(printf '\t')" read -r at kind hash url note; do
    [ -n "$hash" ] || continue
    if tx="$(horizon_tx "$hash")"; then
      if printf '%s' "$tx" | jq -e '.successful==true' >/dev/null; then
        ok "$hash ledger $(printf '%s' "$tx" | jq -r .ledger) memo=$(printf '%s' "$tx" | jq -r '.memo // "-"') ($kind)"
      else
        fail_line "$hash is on chain but not successful ($kind)"; fails=$((fails + 1))
      fi
    else
      fail_line "$hash not found on Horizon ($kind) — testnet reset, or wrong network?"; fails=$((fails + 1))
    fi
  done < "$F"
  [ "$fails" -eq 0 ] && ok "all recorded transactions found on testnet" || die "$fails transaction(s) not confirmed"
fi
