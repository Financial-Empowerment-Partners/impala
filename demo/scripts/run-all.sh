#!/usr/bin/env bash
# The whole suite, in order, with a scorecard: doctor → prepare → build → up → seed → scenarios → verify.
# Writes state/report.md and state/report.json, appends state/timings.tsv. Mandatory steps stop the run
# when they fail; optional lanes (android, soroban testnet) are skipped with a reason when their
# prerequisites are missing. Exit 1 when a mandatory step failed.
# Usage: scripts/run-all.sh [--smoke] [--skip <step>]... [--only <step>] [--no-build] [--keep]
#   --smoke     stack + accounts + custodial payment + roles + reserve/events + verify (~3 minutes once images exist)
#   --skip X    skip step X (e.g. --skip scenario-07-android-emulator)
#   --only X    run only step X (plus doctor)
#   --no-build  do not rebuild images/tools (they must exist)
#   --keep      leave the simulator and emulator running at the end
set -uo pipefail
. "$(dirname "$0")/lib.sh"
load_env 2>/dev/null || true
SMOKE=0; NOBUILD=0; KEEP=0; ONLY=""; SKIPS=" "
while [ $# -gt 0 ]; do
  case "$1" in
    --smoke) SMOKE=1 ;; --no-build) NOBUILD=1 ;; --keep) KEEP=1 ;;
    --skip) SKIPS="$SKIPS$2 "; shift ;; --only) ONLY="$2"; shift ;;
    *) die "unknown option $1" ;;
  esac
  shift
done
mkdir -p "$STATE_DIR" "$RECORDS_DIR"
RUN_AT="$(utc_now)"; RUN_T0="$(now_s)"
# an interrupted run must not leave a headless emulator, a simulator JVM and adb reverse entries behind
on_interrupt() { warn "interrupted: stopping the simulator and the emulator"; "$DEMO_DIR/scripts/simulator.sh" down >/dev/null 2>&1 || true; "$DEMO_DIR/scripts/emulator.sh" down >/dev/null 2>&1 || true; printf '{"status":"interrupted","at":"%s"}\n' "$(utc_now)" > "$STATE_DIR/report.json"; exit 130; }
trap on_interrupt INT TERM
# every host lane reaches the bridge as the same TCP peer: pause until the shared pre-auth budget (30/60 s) is clear
quiet_window() { log "  (pre-auth budget quiet window: ${1}s before $2)"; sleep "$1"; }
ROWS=""   # name \t status \t seconds \t note
MANDATORY_FAILED=0
add_row() { ROWS="$ROWS$1	$2	$3	$4
"; }
skipped_step() { [ -n "$ONLY" ] && [ "$ONLY" != "$1" ] && return 0; case "$SKIPS" in *" $1 "*) return 0 ;; esac; return 1; }

# step <name> <mandatory 0|1> <note-on-skip> <command...>
step() {
  local name="$1" mandatory="$2" skipnote="$3"; shift 3
  local t0 rc note
  if skipped_step "$name"; then add_row "$name" skipped 0 "skipped by flag"; return 0; fi
  if [ -n "$skipnote" ]; then add_row "$name" skipped 0 "$skipnote"; warn "$name: skipped ($skipnote)"; return 0; fi
  hr "$name"
  t0="$(now_s)"
  "$@"; rc=$?
  note=""
  if [ -f "$RECORDS_DIR/$name.json" ]; then note="$(jq -r '(if .passed == null then "" else "\(.passed)/\(.passed + (.failed // 0)) assertions" end) + (if .stellar_hash then "; tx " + .stellar_hash[0:12] + "…" else "" end) | ltrimstr("; ")' "$RECORDS_DIR/$name.json" 2>/dev/null)"; fi
  case "$rc" in
    0) add_row "$name" passed "$(( $(now_s) - t0 ))" "$note" ;;
    3) add_row "$name" ambiguous "$(( $(now_s) - t0 ))" "outcome unknown — do not re-run blindly; see state/records"; [ "$mandatory" = 1 ] && MANDATORY_FAILED=1 ;;
    *) add_row "$name" failed "$(( $(now_s) - t0 ))" "exit $rc; see output above${note:+; $note}"; [ "$mandatory" = 1 ] && MANDATORY_FAILED=1 ;;
  esac
  if [ "$rc" -ne 0 ] && [ "$mandatory" = 1 ]; then warn "$name failed: stopping the mandatory chain"; return 1; fi
  return 0
}

S="$DEMO_DIR/scripts"
step doctor 1 "" "$S/doctor.sh" || { finish=1; }
load_env 2>/dev/null || true
if [ "${finish:-0}" != 1 ]; then
  step prepare 1 "" "$S/prepare.sh" || finish=1
fi
load_env 2>/dev/null || true
if [ "${finish:-0}" != 1 ]; then
  if [ "$NOBUILD" = 1 ]; then add_row build skipped 0 "--no-build"; else step build 1 "" "$S/build.sh" all || finish=1; fi
fi
[ "${finish:-0}" != 1 ] && { step up 1 "" "$S/up.sh" || finish=1; }
[ "${finish:-0}" != 1 ] && { step seed 1 "" "$S/seed.sh" || finish=1; }
load_env 2>/dev/null || true
[ "${finish:-0}" != 1 ] && { step scenario-01-stack 1 "" "$S/scenario-01-stack.sh" || finish=1; }
if grep -ls '"status": "ambiguous"' "$RECORDS_DIR"/scenario-0[2348]-*.json >/dev/null 2>&1; then
  warn "an earlier payment scenario is recorded AMBIGUOUS ($(grep -ls '"status": "ambiguous"' "$RECORDS_DIR"/scenario-0[2348]-*.json | xargs -n1 basename | tr '\n' ' ')): resolve it first (scripts/verify.sh, impalactl activity list, Horizon) and delete the record; no further payments are made"
  add_row scenario-02-custodial-payment skipped 0 "unresolved ambiguous record"; finish=1
fi
[ "${finish:-0}" != 1 ] && { step scenario-02-custodial-payment 1 "" "$S/scenario-02-custodial-payment.sh" || finish=1; }
[ "${finish:-0}" != 1 ] && { step scenario-10-roles 0 "" "$S/scenario-10-roles.sh"; }
[ "${finish:-0}" != 1 ] && { step scenario-11-reserve-events 0 "" "$S/scenario-11-reserve-events.sh"; }
if [ "${finish:-0}" != 1 ] && [ "$SMOKE" != 1 ]; then
  step scenario-03-wallet-cli 0 "" "$S/scenario-03-wallet-cli.sh"
  step scenario-04-operator-cli 0 "" "$S/scenario-04-operator-cli.sh"
  jdknote=""; jdk17_home >/dev/null 2>&1 || jdknote="JDK 17 not found (JAVA17_HOME)"
  step scenario-05-card-issue 0 "$jdknote" "$S/scenario-05-card-issue.sh"
  gsnote="$jdknote"; [ -z "$gsnote" ] && [ ! -f "$REPO_DIR/impala-android-demo/app/google-services.json" ] && gsnote="impala-android-demo/app/google-services.json missing"
  [ -z "$gsnote" ] && ! skipped_step scenario-06-card-login-jvm && quiet_window 61 "the JVM card-login lane"
  step scenario-06-card-login-jvm 0 "$gsnote" "$S/scenario-06-card-login-jvm.sh"
  andnote="$gsnote"; [ -z "$andnote" ] && ! android_lane_wanted && andnote="no emulator + system image (DEMO_ANDROID=$DEMO_ANDROID)"
  [ -z "$andnote" ] && ! skipped_step scenario-07-android-emulator && quiet_window 61 "the emulator lane"
  step scenario-07-android-emulator 0 "$andnote" "$S/scenario-07-android-emulator.sh"
  ! skipped_step scenario-08-payala-relay && quiet_window 61 "the Payala relay lane"
  step scenario-08-payala-relay 0 "" "$S/scenario-08-payala-relay.sh"
  cargonote=""; command -v cargo >/dev/null 2>&1 || cargonote="cargo not found (Rust toolchain; see DEVELOPMENT.md)"
  step scenario-09-soroban 0 "$cargonote" "$S/scenario-09-soroban.sh"
fi
[ "${finish:-0}" != 1 ] && { step verify 1 "" "$S/verify.sh" || true; }
if [ "$KEEP" != 1 ]; then "$S/simulator.sh" down >/dev/null 2>&1 || true; "$S/emulator.sh" down >/dev/null 2>&1 || true; fi

# ---------------------------------------------------------------- report
TOTAL=$(( $(now_s) - RUN_T0 ))
{
  printf '# Impala demo suite — run report\n\n'
  printf -- '- started: %s (UTC), total %ss, engine: %s, repo: %s @ %s\n' "$RUN_AT" "$TOTAL" "${ENGINE:-?}" "$REPO_DIR" "$(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo '?')"
  printf -- '- mode: %s\n\n' "$( [ "$SMOKE" = 1 ] && printf smoke || printf full )"
  printf '| step | status | seconds | note |\n|---|---|---|---|\n'
  printf '%s' "$ROWS" | awk -F'\t' 'NF>=2 {printf "| %s | %s | %s | %s |\n", $1, $2, $3, $4}'
  printf '\n## Testnet transaction ids\n\n'
  if [ -s "$(txid_log_file)" ]; then
    printf '| recorded | kind | hash | explorer |\n|---|---|---|---|\n'
    awk -F'\t' '{printf "| %s | %s | `%s` | %s |\n", $1, $2, $3, $4}' "$(txid_log_file)"
  else printf '_none recorded_\n'; fi
  printf '\n## Records and artifacts\n\n'
  for f in "$RECORDS_DIR"/*.json; do [ -f "$f" ] && printf -- '- `state/records/%s`\n' "$(basename "$f")"; done
  for f in "$ARTIFACTS_DIR"/*; do [ -f "$f" ] && printf -- '- `state/artifacts/%s`\n' "$(basename "$f")"; done
} > "$STATE_DIR/report.md"
printf '%s' "$ROWS" | jq -Rn --arg at "$RUN_AT" --argjson total "$TOTAL" --arg engine "${ENGINE:-}" --arg mode "$( [ "$SMOKE" = 1 ] && printf smoke || printf full )" \
  '{started_at:$at, total_seconds:$total, engine:$engine, mode:$mode, steps:[inputs | select(length>0) | split("\t") | {step:.[0], status:.[1], seconds:(.[2]|tonumber? // 0), note:(.[3] // "")}]}' > "$STATE_DIR/report.json"

log ""
hr "scorecard ($TOTAL s)"
printf '%s' "$ROWS" | awk -F'\t' 'NF>=2 {printf "  %-32s %-10s %6ss  %s\n", $1, $2, $3, $4}' >&2
log "  report: demo/state/report.md (and report.json); testnet ids: scripts/txids.sh --check"
if [ "$MANDATORY_FAILED" = 1 ] || [ "${finish:-0}" = 1 ]; then die "run-all: a mandatory step failed"; fi
ok "run-all: done"
