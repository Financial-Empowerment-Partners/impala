#!/usr/bin/env bash
# Shared helpers for the demo/ scripts. Sourced, not executed. bash 3.2 compatible (macOS /bin/bash):
# no associative arrays, no mapfile, no ${var,,}, no `sed -i` without a suffix.
#
# Conventions (CLAUDE.md house rules applied to a demo kit):
#   - data on stdout, notices on stderr; every Stellar testnet hash is announced by emit_txid
#   - money is integer stroops / cents in bash arithmetic, never floats
#   - a fund-moving call is never resent without its idempotency key; 202 means poll, not retry
#   - scripts are idempotent and re-runnable; state lives under demo/state (gitignored)

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "$DEMO_DIR/.." && pwd)"
STATE_DIR="$DEMO_DIR/state"
# shellcheck disable=SC2034  # read by the scripts that source this file
BUILD_DIR="$DEMO_DIR/build"
BIN_DIR="$DEMO_DIR/bin"
RECORDS_DIR="$STATE_DIR/records"
ARTIFACTS_DIR="$STATE_DIR/artifacts"
PROJECT="impala-suite"
# shellcheck disable=SC2034  # read by build.sh and up.sh
IMAGE_BRIDGE="localhost/$PROJECT/impala-bridge:dev"
HORIZON_URL="https://horizon-testnet.stellar.org"
FRIENDBOT_URL="https://friendbot.stellar.org"
STELLAR_EXPERT_URL="https://stellar.expert/explorer/testnet"
TESTNET_PASSPHRASE="Test SDF Network ; September 2015"

# ---------------------------------------------------------------- output
log()  { printf '%s\n' "$*" >&2; }
info() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m  ok\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33mwarn\033[0m %s\n' "$*" >&2; }
fail_line() { printf '\033[1;31mFAIL\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror\033[0m %s\n' "$*" >&2; exit 1; }
hr()   { printf '\033[1m%s\033[0m\n' "── $* ──" >&2; }

require_cmd() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "missing prerequisite: $c (scripts/doctor.sh lists what is needed)"
  done
}

# ---------------------------------------------------------------- env / state
# .env (secrets, ids, ports) and state/impala.env (addresses written by seed.sh). Variables already set
# in the process environment win over the files.
load_env_file() {
  local line key
  [ -f "$1" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    key="${line%%=*}"
    case "$key" in
      [A-Za-z_]*) ;;
      *) printf 'warn: %s: ignoring malformed line: %.60s\n' "$1" "$line" >&2; continue ;;
    esac
    case "$key" in *[!A-Za-z0-9_]*) printf 'warn: %s: ignoring malformed line: %.60s\n' "$1" "$line" >&2; continue ;; esac
    if eval "[ -n \"\${$key+x}\" ]"; then continue; fi
    # shellcheck disable=SC2163
    export "$line"
  done < "$1"
}

# detect_engine -> docker | podman | '' (whichever answers first; docker preferred)
detect_engine() {
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then echo docker; return 0; fi
  if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then echo podman; return 0; fi
  echo ''
}

load_env() {
  load_env_file "$DEMO_DIR/.env"
  load_env_file "$STATE_DIR/impala.env"
  ENGINE="${CONTAINER_ENGINE:-}"
  [ -n "$ENGINE" ] || ENGINE="$(detect_engine)"
  [ -n "$ENGINE" ] || ENGINE=docker
  case "$ENGINE" in
    docker) COMPOSE_BIN="docker compose" ;;
    podman)
      COMPOSE_BIN="podman compose"
      # podman uses a set-but-empty provider name verbatim, so empty must mean "unset = podman's own search"
      if [ -n "${PODMAN_COMPOSE_PROVIDER:-}" ]; then export PODMAN_COMPOSE_PROVIDER; else unset PODMAN_COMPOSE_PROVIDER; fi
      export PODMAN_COMPOSE_WARNING_LOGS="${PODMAN_COMPOSE_WARNING_LOGS:-false}" ;;
    *) die "CONTAINER_ENGINE must be docker or podman (got '$ENGINE')" ;;
  esac
  BRIDGE_URL="http://127.0.0.1:${BRIDGE_PORT:-8080}"
  UI_URL="http://localhost:${UI_PORT:-3000}"
  OPENBAO_URL="http://127.0.0.1:${OPENBAO_PORT:-8200}"
  PAYALA_URL="http://127.0.0.1:${PAYALA_PORT:-4000}"
  SIM_PORT="${SIM_PORT:-9443}"
  export ENGINE COMPOSE_BIN BRIDGE_URL UI_URL OPENBAO_URL PAYALA_URL SIM_PORT
  mkdir -p "$STATE_DIR" "$RECORDS_DIR" "$ARTIFACTS_DIR"
}

require_env() {
  local v
  for v in "$@"; do
    eval "[ -n \"\${$v:-}\" ]" || die "missing $v (run scripts/prepare.sh, or scripts/seed.sh for addresses)"
  done
}

# compose <args...>: engine-agnostic compose invocation (word splitting of COMPOSE_BIN is intended)
compose() {
  # shellcheck disable=SC2086
  $COMPOSE_BIN -p "$PROJECT" -f "$DEMO_DIR/compose.yaml" "$@"
}

engine_ready() {
  case "$ENGINE" in
    docker) docker info >/dev/null 2>&1 || die "Docker daemon not reachable. OrbStack: run 'orb start' (or open OrbStack.app); Docker Desktop: start it." ;;
    podman) podman info >/dev/null 2>&1 || die "Podman not reachable. Run 'podman machine start' (see scripts/doctor.sh)." ;;
  esac
}

image_exists() {
  case "$ENGINE" in
    docker) docker image inspect "$1" >/dev/null 2>&1 ;;
    podman) podman image exists "$1" ;;
  esac
}

# stack_running -> 0 if any container of the project exists
stack_running() { [ -n "$(compose ps -q 2>/dev/null | head -1)" ]; }

# psql helper runs inside the postgres container (no host port needed). Pass psql args, e.g. -c "..." or -f - with stdin.
psql_impala() { compose exec -T postgres psql -U postgres -d impala -v ON_ERROR_STOP=1 "$@"; }
# payala_get <path> -> the Payala stub's JSON answer (payala-stub/README.md; no auth exists, and the stub's
# request journal shows that none was ever sent)
payala_get() { curl -fsS "$PAYALA_URL$1"; }

# ---------------------------------------------------------------- waiting
# wait_http <url> [tries] [sleep_seconds]: poll from the host until the URL answers 2xx/3xx
wait_http() {
  local url="$1" tries="${2:-60}" pause="${3:-2}" i=0
  until curl -fsS -o /dev/null "$url"; do
    i=$((i + 1))
    if [ "$i" -ge "$tries" ]; then die "timeout waiting for $url"; fi
    sleep "$pause"
  done
}
# port_open <port> -> 0 when something listens on 127.0.0.1:<port> (bash's /dev/tcp probe: no lsof/ss needed)
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
# wait_port <port> [tries] [sleep_seconds]
wait_port() {
  local port="$1" tries="${2:-60}" pause="${3:-1}" i=0
  until port_open "$port"; do
    i=$((i + 1))
    if [ "$i" -ge "$tries" ]; then return 1; fi
    sleep "$pause"
  done
}

# ---------------------------------------------------------------- encoding helpers (no xxd needed)
bin_to_hex() { od -An -v -tx1 | tr -d ' \n'; }
hex_to_bin() { printf "$(sed 's/../\\x&/g')"; }
b64_to_hex() { openssl base64 -d -A | bin_to_hex; }
hex_to_b64() { hex_to_bin | openssl base64 -A; }
uuid_hex()   { printf '%s' "$1" | tr -d '-' | tr 'A-F' 'a-f'; }
utc_now()    { date -u +%Y-%m-%dT%H:%M:%SZ; }
# utc_from_epoch <seconds> -> YYYY-MM-DDTHH:MM:SSZ (BSD date -r / GNU date -d @)
utc_from_epoch() { date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }
now_s() { date +%s; }

# ---------------------------------------------------------------- Impala bridge helpers
# bridge_api <METHOD> <path> [token] [json-body]; prints the body. The HTTP status is available
# afterwards via $(http_code) (kept in a per-process temp file because callers use command substitution).
HTTP_CODE_FILE="$(mktemp "${TMPDIR:-/tmp}/impala-suite-http.XXXXXX")"
cleanup_tmp() { rm -f "$HTTP_CODE_FILE"; }
trap cleanup_tmp EXIT
http_code() { cat "$HTTP_CODE_FILE" 2>/dev/null || echo 000; }
# Secrets never travel in argv (CLAUDE.md): the body goes to curl on stdin and the bearer token through a
# 0600 header file (`-H @file`), so neither a password nor a JWT is visible in `ps`.
bridge_api() {
  local method="$1" path="$2" token="${3:-}" body="${4:-}" out hdr
  local args=(-sS -X "$method" -H 'Content-Type: application/json' -w '\n%{http_code}')
  hdr="$(mktemp "${TMPDIR:-/tmp}/impala-suite-hdr.XXXXXX")"
  if [ -n "$token" ]; then printf 'Authorization: Bearer %s\n' "$token" > "$hdr"; args+=(-H "@$hdr"); fi
  if [ -n "$body" ]; then args+=(--data-binary @-); fi
  out="$(printf '%s' "$body" | curl "${args[@]}" "$BRIDGE_URL$path")" || { rm -f "$hdr"; printf '000' > "$HTTP_CODE_FILE"; return 1; }
  rm -f "$hdr"
  printf '%s' "${out##*$'\n'}" > "$HTTP_CODE_FILE"
  printf '%s\n' "${out%$'\n'*}"
}

# bridge_login <username> <password> -> temporal token (fails loudly; the API answers 200 even on failure)
# All host lanes reach the bridge as ONE TCP peer (the engine gateway), so they share the pre-auth budget of
# 30 requests per 60 s. A 429 here is paced, not failed: wait the whole window once, then retry.
bridge_login() {
  local body resp
  body="$(U="$1" PW="$2" jq -cn '{username:env.U,password:env.PW}')"   # env, not argv
  resp="$(bridge_api POST /token "" "$body")" || die "POST /token failed"
  if [ "$(http_code)" = "429" ]; then
    warn "pre-auth budget exhausted (429: 30 /token calls per 60 s from this host); waiting 61 s for the window to clear, then one retry"
    sleep 61
    resp="$(bridge_api POST /token "" "$body")" || die "POST /token failed"
  fi
  printf '%s' "$resp" | jq -er 'select(.success==true) | .temporal_token' 2>/dev/null \
    || die "bridge login failed for $1: $(printf '%s' "$resp" | jq -r '.message // .error.message // .' 2>/dev/null)"
}
# bridge_refresh_token <username> <password> -> refresh token (impalactl/e2e lanes want the pair)
bridge_refresh_token() {
  local body resp
  body="$(U="$1" PW="$2" jq -cn '{username:env.U,password:env.PW}')"
  resp="$(bridge_api POST /token "" "$body")" || die "POST /token failed"
  printf '%s' "$resp" | jq -er 'select(.success==true) | .refresh_token' 2>/dev/null || die "bridge login failed for $1"
}

# bridge_authenticate <account_id> <password>: sets the first password (ALLOW_OPEN_REGISTRATION) or verifies it; prints the action
bridge_authenticate() {
  local body resp
  body="$(A="$1" PW="$2" jq -cn '{account_id:env.A,password:env.PW}')"
  resp="$(bridge_api POST /authenticate "" "$body")" || die "POST /authenticate failed"
  printf '%s' "$resp" | jq -e '.success==true' >/dev/null \
    || die "authenticate failed for $1: $(printf '%s' "$resp" | jq -r '.message // .')"
  printf '%s' "$resp" | jq -r '.action'
}

# jwt_claim <jwt> <claim> -> the claim value from the (unverified) payload
jwt_claim() {
  printf '%s' "$1" | cut -d. -f2 | tr '_-' '/+' | awk '{l=length($0)%4; if(l==2) $0=$0"=="; else if(l==3) $0=$0"="; print}' \
    | openssl base64 -d -A 2>/dev/null | jq -r ".$2"
}

admin_jwt() { bridge_login "$PAYALA_ADMIN_ID" "$IMPALA_ADMIN_PASSWORD"; }

# transit_canary_ok -> 0 when OpenBao still holds the Transit key that sealed the bridge's seeds (see openbao-init.sh)
transit_canary_ok() {
  compose run --rm --no-deps --entrypoint sh openbao-init -c 'bao write -field=plaintext transit/decrypt/impala-seeds ciphertext="$(cat /bootstrap/transit-canary.txt)" 2>/dev/null | base64 -d' 2>/dev/null | grep -q 'impala-suite-canary'
}

wait_bridge() {
  wait_http "$BRIDGE_URL/readyz" "${1:-30}" 2
  [ "$(curl -fsS "$BRIDGE_URL/network" | jq -r .network_passphrase)" = "$TESTNET_PASSPHRASE" ] || die "bridge is not on testnet"
}

# ---------------------------------------------------------------- Stellar helpers
horizon_account_exists() { curl -fsS -o /dev/null "$HORIZON_URL/accounts/$1" 2>/dev/null; }
horizon_native_balance() {
  curl -fsS "$HORIZON_URL/accounts/$1" 2>/dev/null | jq -r '.balances[] | select(.asset_type=="native") | .balance' \
    || { warn "$1: not found on Horizon (unfunded, or Horizon unreachable)"; echo 0; }
}
horizon_tx() { curl -fsS "$HORIZON_URL/transactions/$1" 2>/dev/null; }
# horizon_wait_tx <hash> [tries] -> the transaction JSON once Horizon has it
horizon_wait_tx() {
  local i=0 tx
  until tx="$(horizon_tx "$1")"; do i=$((i + 1)); [ "$i" -le "${2:-20}" ] || return 1; sleep 3; done
  printf '%s' "$tx"
}
friendbot_fund() {
  local h
  if horizon_account_exists "$1"; then
    ok "$1 already exists on testnet"
  else
    info "funding $1 via Friendbot"
    h="$(curl -fsS "$FRIENDBOT_URL/?addr=$1" | jq -er .hash)" || die "friendbot failed for $1"
    emit_txid friendbot "$h" "funding $1"
  fi
}

# ---------------------------------------------------------------- testnet transaction ids
# Every Stellar testnet transaction the kit creates or sees is announced with its full hash and the
# URLs to look it up elsewhere (Horizon, stellar.expert), and appended once to a TSV log:
#   state/testnet-txids.tsv (override with DEMO_TXID_FILE)   columns: utc  kind  hash  explorer_url  note
# A machine-readable line goes to stdout so a harness can grep it:  TESTNET_TXID <tab> kind <tab> hash <tab> url
txid_log_file() { printf '%s' "${DEMO_TXID_FILE:-$STATE_DIR/testnet-txids.tsv}"; }
horizon_tx_url()  { printf '%s/transactions/%s' "$HORIZON_URL" "$1"; }
explorer_tx_url() { printf '%s/tx/%s' "$STELLAR_EXPERT_URL" "$1"; }
explorer_account_url() { printf '%s/account/%s' "$STELLAR_EXPERT_URL" "$1"; }
txid_recorded() { grep -q "	$1	" "$(txid_log_file)" 2>/dev/null; } # <hash> -> 0 when already in the log
# emit_txid <kind> <hash> [note]
emit_txid() {
  local kind="$1" hash="$2" note="${3:-}" f
  [ "${#hash}" -eq 64 ] || { warn "emit_txid: '$hash' is not a 64-hex transaction hash"; return 0; }
  f="$(txid_log_file)"
  log "  testnet tx $hash  ($kind${note:+; $note})"
  log "    horizon  $(horizon_tx_url "$hash")"
  log "    explorer $(explorer_tx_url "$hash")"
  printf 'TESTNET_TXID\t%s\t%s\t%s\n' "$kind" "$hash" "$(explorer_tx_url "$hash")"
  mkdir -p "$(dirname "$f")"
  if ! grep -q "	$hash	" "$f" 2>/dev/null; then
    printf '%s\t%s\t%s\t%s\t%s\n' "$(utc_now)" "$kind" "$hash" "$(explorer_tx_url "$hash")" "$note" >> "$f"
  fi
}

# ---------------------------------------------------------------- amount conversions (integer math, bash 3.2)
# xlm_to_stroops "12.3400000" -> 123400000 ; stroops_to_xlm 123400000 -> "12.3400000"
xlm_to_stroops() {
  local s="$1" int frac
  case "$s" in *.*) int="${s%.*}"; frac="${s#*.}" ;; *) int="$s"; frac="" ;; esac
  frac="$(printf '%s0000000' "$frac" | cut -c1-7)"
  printf '%d' "$(( ${int:-0} * 10000000 + 10#$frac ))"
}
stroops_to_xlm() { printf '%d.%07d' "$(( $1 / 10000000 ))" "$(( $1 % 10000000 ))"; }
# cents_to_stroops <cents> -> stroops, or exit 1 when the demo rate does not give a whole number of stroops
cents_to_stroops() {
  [ $(( $1 * 10000000 % DEMO_CENTS_PER_XLM )) -eq 0 ] || return 1
  printf '%d' "$(( $1 * 10000000 / DEMO_CENTS_PER_XLM ))"
}

# ---------------------------------------------------------------- records, assertions, timings
# record_json <name> <json>: atomic write of state/records/<name>.json
record_json() { mkdir -p "$RECORDS_DIR"; printf '%s\n' "$2" | jq . > "$RECORDS_DIR/$1.json.tmp" && mv "$RECORDS_DIR/$1.json.tmp" "$RECORDS_DIR/$1.json"; }
record_path() { printf '%s/%s.json' "$RECORDS_DIR" "$1"; }
# record_get <name> <jq filter> -> value, '' when absent
record_get() { jq -r "$2 // empty" "$RECORDS_DIR/$1.json" 2>/dev/null || true; }
# timing <label> <seconds> <status>: append to state/timings.tsv
timing() { mkdir -p "$STATE_DIR"; printf '%s\t%s\t%s\t%s\n' "$(utc_now)" "$1" "$2" "$3" >> "$STATE_DIR/timings.tsv"; }

# assertions: check <label> <command> [args...]  (the command's exit code decides; output is discarded)
#             check_jq <label> <jq filter> <json>  (the filter must evaluate true)
PASSES=0; FAILS=0
check() { local label="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$label"; PASSES=$((PASSES + 1)); else fail_line "$label"; FAILS=$((FAILS + 1)); fi; }
check_jq() { local label="$1" filter="$2" json="$3"; if printf '%s' "$json" | jq -e "$filter" >/dev/null 2>&1; then ok "$label"; PASSES=$((PASSES + 1)); else fail_line "$label"; FAILS=$((FAILS + 1)); fi; }
# check_eval <label> <shell expression>: evaluated in THIS shell, so lib functions (compose, bridge_api, psql_impala…) are available
# (evaluated in a subshell without pipefail: `cmd | grep -q` must not fail because grep closed the pipe early)
check_eval() { local label="$1" expr="$2"; if ( set +o pipefail; eval "$expr" ) >/dev/null 2>&1; then ok "$label"; PASSES=$((PASSES + 1)); else fail_line "$label"; FAILS=$((FAILS + 1)); fi; }
# finish_scenario <name> <extra-json-object> <started-epoch>: writes the record with the tally and exits 1 on failures
finish_scenario() {
  local name="$1" extra="${2:-{\}}" started="${3:-$(now_s)}" secs status
  secs=$(( $(now_s) - started ))
  if [ "$FAILS" -eq 0 ]; then status=passed; else status=failed; fi
  record_json "$name" "$(printf '%s' "$extra" | jq -c --arg n "$name" --arg s "$status" --argjson p "$PASSES" --argjson f "$FAILS" --argjson t "$secs" --arg at "$(utc_now)" \
    '. + {scenario:$n, status:$s, passed:$p, failed:$f, seconds:$t, finished_at:$at}')"
  timing "$name" "$secs" "$status"
  log ""
  if [ "$FAILS" -eq 0 ]; then ok "$name: all $PASSES assertions passed (${secs}s)"; else die "$name: $FAILS of $(( PASSES + FAILS )) assertions failed (${secs}s)"; fi
}

# ---------------------------------------------------------------- host lanes: JDK, Gradle, Android SDK, tools
# jdk17_home -> the JDK 17 that LAUNCHES Gradle (the CAP/Ant task runs in the Gradle JVM; Kotlin uses the 21 toolchain)
jdk17_home() {
  if [ -n "${JAVA17_HOME:-}" ] && [ -x "$JAVA17_HOME/bin/java" ]; then printf '%s' "$JAVA17_HOME"; return 0; fi
  if [ -x /usr/libexec/java_home ]; then /usr/libexec/java_home -v 17 2>/dev/null && return 0; fi
  if [ -n "${JAVA_HOME:-}" ] && "$JAVA_HOME/bin/java" -version 2>&1 | grep -q '"17\.'; then printf '%s' "$JAVA_HOME"; return 0; fi
  return 1
}
# gradle_in <project-dir> <args...>: run the project's wrapper on JDK 17 (subshell cd; the repo is never modified)
gradle_in() {
  local dir="$1"; shift
  local jh
  jh="$(jdk17_home)" || die "JDK 17 not found (set JAVA17_HOME): needed to launch Gradle for $dir"
  (cd "$dir" && JAVA_HOME="$jh" ./gradlew "$@")
}
gradle_card() { gradle_in "$REPO_DIR/impala-card" "$@"; }
gradle_app()  { gradle_in "$REPO_DIR/impala-android-demo" "$@"; }

# android_sdk_root -> the SDK that holds emulator/ and system-images/ (DEMO_ANDROID_SDK_ROOT, ANDROID_SDK_ROOT, ANDROID_HOME, ~/Library/Android/sdk)
android_sdk_root() {
  local c
  for c in "${DEMO_ANDROID_SDK_ROOT:-}" "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}" "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
    [ -n "$c" ] && [ -x "$c/emulator/emulator" ] && { printf '%s' "$c"; return 0; }
  done
  return 1
}
adb_bin() {
  local r
  if r="$(android_sdk_root)" && [ -x "$r/platform-tools/adb" ]; then printf '%s' "$r/platform-tools/adb"; return 0; fi
  command -v adb 2>/dev/null
}
emulator_bin()   { local r; r="$(android_sdk_root)" && printf '%s' "$r/emulator/emulator"; }
avdmanager_bin() { local r; r="$(android_sdk_root)" && [ -x "$r/cmdline-tools/latest/bin/avdmanager" ] && printf '%s' "$r/cmdline-tools/latest/bin/avdmanager"; }
sdkmanager_bin() { local r; r="$(android_sdk_root)" && [ -x "$r/cmdline-tools/latest/bin/sdkmanager" ] && printf '%s' "$r/cmdline-tools/latest/bin/sdkmanager"; }
system_image_present() {
  local r dir
  r="$(android_sdk_root)" || return 1
  dir="$r/$(printf '%s' "${DEMO_SYSTEM_IMAGE:-system-images;android-34;google_apis;arm64-v8a}" | tr ';' '/')"
  [ -f "$dir/package.xml" ] && [ -f "$dir/kernel-ranchu" ]
}
# android_lane_wanted -> 0 when the emulator lane should run (DEMO_ANDROID=1, or auto with an emulator + image present)
android_lane_wanted() {
  case "${DEMO_ANDROID:-auto}" in
    1|true|yes) return 0 ;;
    0|false|no) return 1 ;;
    *) android_sdk_root >/dev/null 2>&1 && system_image_present ;;
  esac
}

lumencli_bin()  { [ -x "$BIN_DIR/lumencli" ] && printf '%s' "$BIN_DIR/lumencli"; }
impalactl_bin() { [ -x "$BIN_DIR/impalactl" ] && printf '%s' "$BIN_DIR/impalactl"; }
