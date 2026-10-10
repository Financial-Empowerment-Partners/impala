#!/usr/bin/env bash
# Scenario 10 — roles and the capability matrix: three new accounts are granted the lateral privileged
# roles (treasurer, key-custodian, auditor) by the admin; each grant revokes the target's existing tokens
# (auth-epoch bump), the next login carries the role in the JWT, and the capability matrix
# (impala-ui/tests/fixtures/role-capabilities.json, the one table both the bridge and the UI assert against)
# decides what each role may read or change. The admin itself is an "effective admin" through
# ADMIN_ACCOUNT_IDS and is reported as allowlisted. Read-mostly; no money moves.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
require_cmd curl jq
require_env PAYALA_ADMIN_ID IMPALA_ADMIN_PASSWORD
LUMEN="$(lumencli_bin)" || die "bin/lumencli missing: run scripts/build.sh tools"
t0="$(now_s)"
hr "scenario 10: roles and the capability matrix"
wait_bridge 10
ADMIN_JWT="$(admin_jwt)"
FIXTURE="$REPO_DIR/impala-ui/tests/fixtures/role-capabilities.json"
check "the shared role → capability fixture exists" [ -f "$FIXTURE" ]
check_eval "fixture lists the seven roles" "jq -e '.roles|length==7' '$FIXTURE' >/dev/null"

accounts="$(bridge_api GET '/accounts?per_page=50' "$ADMIN_JWT")"
check_jq "the admin is an effective admin: role admin and allowlisted (ADMIN_ACCOUNT_IDS)" "[.data[]|select(.payala_account_id==\"$PAYALA_ADMIN_ID\")|.role==\"admin\" and (.allowlisted // false)==true]|all" "$accounts"

# role_user <role> -> creates (or reuses) demo account role-<role>, sets its password, returns its id
ROLE_PW="$(openssl rand -hex 12)"
role_user() { # <role>
  local id="30000000-0000-4000-8000-00000000000$1" g
  g="$(printf '%s' "$accounts" | jq -r --arg id "$id" '.data[]|select(.payala_account_id==$id)|.stellar_account_id')"
  if [ -z "$g" ]; then
    g="$(LUMEN_NETWORK=testnet "$LUMEN" account new 2>/dev/null | grep -Eo 'G[A-Z2-7]{55}' | head -n1)"
    bridge_api POST /account "$ADMIN_JWT" "$(jq -cn --arg g "$g" --arg id "$id" --arg f "Role" --arg l "$2" '{stellar_account_id:$g,payala_account_id:$id,first_name:$f,last_name:$l,affiliation:"Demo"}')" >/dev/null
    [ "$(http_code)" = "200" ] || die "POST /account for $id failed ($(http_code))"
  fi
  bridge_authenticate "$id" "$ROLE_PW" >/dev/null 2>&1 || true   # sets the first password; verifies it afterwards
  printf '%s' "$id"
}
# expect <label> <jwt> <method> <path> <expected http code> [body]
expect() {
  local label="$1" jwt="$2" method="$3" path="$4" want="$5" body="${6:-}"
  bridge_api "$method" "$path" "$jwt" "$body" >/dev/null 2>&1 || true
  check "$label → $want" [ "$(http_code)" = "$want" ]
}

info "1/4 three accounts, view-only to begin with"
T_ID="$(role_user 1 Treasurer)"; K_ID="$(role_user 2 Custodian)"; A_ID="$(role_user 3 Auditor)"
T0_T="$(bridge_login "$T_ID" "$ROLE_PW")"; T0_K="$(bridge_login "$K_ID" "$ROLE_PW")"; T0_A="$(bridge_login "$A_ID" "$ROLE_PW")"
check "fresh accounts carry role view-only in their JWT" sh -c "[ '$(jwt_claim "$T0_T" role)' = view-only ] && [ '$(jwt_claim "$T0_K" role)' = view-only ] && [ '$(jwt_claim "$T0_A" role)' = view-only ]"
expect "view-only: GET /admin/keys" "$T0_T" GET /admin/keys 403
expect "view-only: GET /admin/custody/policy" "$T0_T" GET /admin/custody/policy 403
expect "view-only: GET /admin/events" "$T0_A" GET '/admin/events?since=0&limit=1' 403

info "2/4 grants by the admin (PUT /admin/accounts/{id}/role): each one revokes the target's current tokens"
grant() { # <id> <role>
  local resp; resp="$(bridge_api PUT "/admin/accounts/$1/role" "$ADMIN_JWT" "$(jq -cn --arg r "$2" '{role:$r}')")"
  check "grant $2 to $1 accepted" [ "$(http_code)" = "200" ]
  printf '%s' "$resp"
}
grant "$T_ID" treasurer >/dev/null; grant "$K_ID" key-custodian >/dev/null; grant "$A_ID" auditor >/dev/null
sleep 1
expect "treasurer's pre-grant token is revoked by the epoch bump: GET /account" "$T0_T" GET "/account?payala_account_id=$T_ID" 401
expect "auditor's pre-grant token is revoked by the epoch bump" "$T0_A" GET "/account?payala_account_id=$A_ID" 401

info "3/4 the next login carries the role, and the capability matrix decides"
T_JWT="$(bridge_login "$T_ID" "$ROLE_PW")"; K_JWT="$(bridge_login "$K_ID" "$ROLE_PW")"; A_JWT="$(bridge_login "$A_ID" "$ROLE_PW")"
check "new JWTs carry treasurer / key-custodian / auditor" sh -c "[ '$(jwt_claim "$T_JWT" role)' = treasurer ] && [ '$(jwt_claim "$K_JWT" role)' = key-custodian ] && [ '$(jwt_claim "$A_JWT" role)' = auditor ]"
# fixture: ReadCustody = admin, treasurer, auditor; ManageCustody = admin, treasurer; ReadKeys = admin, key-custodian, auditor;
#          ManageKeys = admin, key-custodian; ReadEvents = admin, auditor; ReadAccounts = admin, auditor, key-custodian; ReadReserve = admin, treasurer, auditor
expect "treasurer: GET /admin/custody/policy (ReadCustody)" "$T_JWT" GET /admin/custody/policy 200
expect "treasurer: GET /admin/exchange-reserve (ReadReserve)" "$T_JWT" GET /admin/exchange-reserve 200
expect "treasurer: GET /admin/keys (ReadKeys not held)" "$T_JWT" GET /admin/keys 403
expect "treasurer: GET /admin/events (ReadEvents not held)" "$T_JWT" GET '/admin/events?since=0&limit=1' 403
expect "key-custodian: GET /admin/keys (ReadKeys)" "$K_JWT" GET /admin/keys 200
expect "key-custodian: GET /accounts (ReadAccounts)" "$K_JWT" GET '/accounts?per_page=1' 200
expect "key-custodian: GET /admin/custody/policy (ReadCustody not held)" "$K_JWT" GET /admin/custody/policy 403
expect "auditor: GET /admin/events (ReadEvents)" "$A_JWT" GET '/admin/events?since=0&limit=1' 200
expect "auditor: GET /admin/keys (ReadKeys, read-only oversight)" "$A_JWT" GET /admin/keys 200
expect "auditor: GET /admin/custody/policy (ReadCustody)" "$A_JWT" GET /admin/custody/policy 200
expect "auditor: PUT /admin/custody/policy (ManageCustody not held)" "$A_JWT" PUT /admin/custody/policy 403 '{"per_tx_max_stroops":1}'
expect "auditor: PUT /admin/accounts/{id}/role (governance is admin-only)" "$A_JWT" PUT "/admin/accounts/$T_ID/role" 403 '{"role":"admin"}'
expect "treasurer: cannot grant roles either" "$T_JWT" PUT "/admin/accounts/$A_ID/role" 403 '{"role":"admin"}'

info "4/4 the grants are visible to the admin and auditable"
accounts="$(bridge_api GET '/accounts?per_page=50' "$ADMIN_JWT")"
check_jq "accounts list shows the three roles" "([.data[]|select(.payala_account_id==\"$T_ID\")|.role]==[\"treasurer\"]) and ([.data[]|select(.payala_account_id==\"$K_ID\")|.role]==[\"key-custodian\"]) and ([.data[]|select(.payala_account_id==\"$A_ID\")|.role]==[\"auditor\"])" "$accounts"
events="$(bridge_api GET '/admin/events?since=0&limit=500' "$ADMIN_JWT")"
check_jq "account.role_changed events were emitted for the grants" '([.events[]|select(.event_type=="account.role_changed")]|length)>=3' "$events"
log "  UI: $UI_URL -> Accounts shows the roles; the Roles page is the matrix"

finish_scenario scenario-10-roles "$(jq -cn --arg t "$T_ID" --arg k "$K_ID" --arg a "$A_ID" '{treasurer:$t, key_custodian:$k, auditor:$a}')" "$t0"
