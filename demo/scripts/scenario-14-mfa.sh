#!/usr/bin/env bash
# Scenario 14 — multi-factor sign-in end to end (docs/mfa-card-pin-biometrics.md), on top of the
# SEP-10 card auth of scenario 12. A card-held Stellar key already signs the holder in; this lane adds
# the second-factor handling the bridge now enforces:
#   1. a fresh password session starts single-factor (GET /mfa/status);
#   2. TOTP step-up: enrol a TOTP method (POST /mfa), compute the code with a stdlib helper, step up
#      (POST /mfa/step-up) and watch the session become multi-factor;
#   3. phone device-key step-up: an openssl P-256 key (the stand-in for an Android Keystore key) enrols
#      by signing a /mfa/challenge, then steps up a fresh single-factor session to multi-factor;
#   4. the admin MFA surfaces: the per-account factor summary, the mandate (which signs the account out),
#      the bridge refusing a required-but-single-factor session (403 mfa_required) until it steps up, a
#      TOTP code refused the second time (a code is single-use), and device-key recovery. The mandate is
#      lifted again, on any exit, so the holder is left as it was.
# The card PIN proof over the same SEP-10 tap (card + PIN in one tap) is exercised by the applet/SDK/lib
# unit suites and CardSep10E2ETest; this lane covers the factors a browser or script drives.
# Crypto: scripts/mfa-factor.py (TOTP, stdlib only; it also builds the IMPALA-DKEY: assertion message) and
# openssl for the P-256 device key — no app, no emulator.
# Usage: scripts/scenario-14-mfa.sh
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
require_cmd curl jq python3 openssl
require_env DEMO_HOLDER_ID IMPALA_HOLDER_PASSWORD PAYALA_ADMIN_ID IMPALA_ADMIN_PASSWORD HOLDER_G
t0="$(now_s)"
hr "scenario 14: multi-factor sign-in (holder $DEMO_HOLDER_ID)"
wait_bridge 10

MFA="$DEMO_DIR/scripts/mfa-factor.py"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/impala-mfa.XXXXXX")"
HOLDER="$DEMO_HOLDER_ID"
# Whatever happens below, the holder is left as it was found: a mandate this run turned on is lifted and a
# device key it enrolled is removed, so a failed assertion cannot leave the account locked behind MFA.
MANDATED=0; KEY_ID=""; KEY_LIVE=0; ADMIN_JWT=""
restore() {
  if [ -n "$ADMIN_JWT" ]; then
    [ "$MANDATED" = 1 ] && { bridge_api PUT "/admin/accounts/$HOLDER/mfa-policy" "$ADMIN_JWT" '{"required":false}' >/dev/null 2>&1 || true; }
    [ "$KEY_LIVE" = 1 ] && { bridge_api DELETE "/admin/accounts/$HOLDER/mfa/device-keys/$KEY_ID" "$ADMIN_JWT" >/dev/null 2>&1 || true; }
  fi
  rm -rf "$WORK"; cleanup_tmp
}
trap restore EXIT

# amr_has <token> <factor> : the session's amr (from GET /mfa/status) contains <factor>.
status_of() { bridge_api GET /mfa/status "$1"; }

info "1/4 a fresh password session starts single-factor"
HJWT="$(bridge_login "$HOLDER" "$IMPALA_HOLDER_PASSWORD")"
st="$(status_of "$HJWT")"
check_jq "GET /mfa/status: the password session carries amr=[pwd] and is not multi-factor" \
  '(.amr | index("pwd")) != null and (.amr | index("mfa") == null) and .mfa != true' "$st"
check_jq "the holder is not required to be multi-factor yet (single-factor is allowed)" \
  '.required != true and .satisfied == true' "$st"

info "2/4 TOTP step-up"
enroll="$(bridge_api POST /mfa "$HJWT" "$(jq -cn --arg a "$HOLDER" '{account_id:$a, mfa_type:"totp"}')")"
check_jq "POST /mfa enrols TOTP and returns an otpauth provisioning URI" \
  '.success == true and (.provisioning_uri | test("^otpauth://totp/"))' "$enroll"
# The shared secret rides the provisioning URI (?secret=...), exactly what an authenticator reads.
SECRET="$(printf '%s' "$enroll" | jq -r '.provisioning_uri' | sed -n 's/.*[?&]secret=\([A-Z2-7]*\).*/\1/p')"
[ -n "$SECRET" ] || die "no TOTP secret in the provisioning URI"
CODE="$(python3 "$MFA" totp "$SECRET")"
stepup="$(bridge_api POST /mfa/step-up "$HJWT" "$(jq -cn --arg c "$CODE" '{mfa_type:"totp", code:$c}')")"
check_jq "POST /mfa/step-up (totp) succeeds and the new amr is multi-factor (pwd + otp + mfa)" \
  '.success == true and (.amr | index("otp")) != null and (.amr | index("mfa")) != null' "$stepup"
HJWT_MFA="$(printf '%s' "$stepup" | jq -r '.temporal_token // empty')"
[ -n "$HJWT_MFA" ] || die "step-up returned no temporal token"
check_jq "GET /mfa/status on the stepped-up token reports multi-factor" '.mfa == true' "$(status_of "$HJWT_MFA")"

info "3/4 phone device-key step-up (an openssl P-256 key stands in for the Android Keystore key)"
openssl ecparam -genkey -name prime256v1 -noout -out "$WORK/dev.pem" 2>/dev/null
DEV_PUB="$(openssl ec -in "$WORK/dev.pem" -pubout -outform DER 2>/dev/null | tail -c 65 | bin_to_hex)"
check "the device public key is a 65-byte uncompressed P-256 point" sh -c "[ \"${DEV_PUB:0:2}\" = 04 ] && [ ${#DEV_PUB} -eq 130 ]"
# Enrol: prove possession by signing a fresh challenge with purpose ENROLL (0x01).
ch1="$(bridge_api POST /mfa/challenge "$HJWT_MFA" '{}' | jq -r '.challenge')"
python3 "$MFA" device-message "$HOLDER" 1 "$ch1" > "$WORK/enroll.bin"
ENROLL_SIG="$(openssl dgst -sha256 -sign "$WORK/dev.pem" "$WORK/enroll.bin" | bin_to_hex)"
reg="$(bridge_api POST /mfa/device-keys "$HJWT_MFA" "$(jq -cn --arg p "$DEV_PUB" --arg c "$ch1" --arg s "$ENROLL_SIG" \
  '{public_key:$p, label:"demo openssl key", platform:"demo", user_verification:"none", challenge:$c, signature:$s}')")"
check_jq "POST /mfa/device-keys registers the device key and returns its key_id" \
  '.success == true and (.key_id | test("^[0-9a-f-]{36}$"))' "$reg"
KEY_ID="$(printf '%s' "$reg" | jq -r '.key_id // empty')"
[ -n "$KEY_ID" ] && KEY_LIVE=1
# Step up a FRESH single-factor session with the device key alone: pwd + dev is two factor kinds.
HJWT2="$(bridge_login "$HOLDER" "$IMPALA_HOLDER_PASSWORD")"
ch2="$(bridge_api POST /mfa/challenge "$HJWT2" '{}' | jq -r '.challenge')"
python3 "$MFA" device-message "$HOLDER" 2 "$ch2" > "$WORK/stepup.bin"
STEPUP_SIG="$(openssl dgst -sha256 -sign "$WORK/dev.pem" "$WORK/stepup.bin" | bin_to_hex)"
dstep="$(bridge_api POST /mfa/step-up "$HJWT2" "$(jq -cn --arg c "$ch2" --arg k "$KEY_ID" --arg s "$STEPUP_SIG" \
  '{mfa_type:"device", challenge:$c, key_id:$k, device_signature:$s}')")"
check_jq "POST /mfa/step-up (device) makes a password session multi-factor (pwd + dev + mfa)" \
  '.success == true and (.amr | index("dev")) != null and (.amr | index("mfa")) != null' "$dstep"
# A tampered signature is refused: the second factor is really verified. (A fresh
# challenge is needed since the step-up above consumed ch2's single-use claim.)
HJWT_BAD="$(bridge_login "$HOLDER" "$IMPALA_HOLDER_PASSWORD")"
ch3="$(bridge_api POST /mfa/challenge "$HJWT_BAD" '{}' | jq -r '.challenge')"
bridge_api POST /mfa/step-up "$HJWT_BAD" \
  "$(jq -cn --arg c "$ch3" --arg k "$KEY_ID" '{mfa_type:"device", challenge:$c, key_id:$k, device_signature:"deadbeef"}')" >/dev/null 2>&1 || true
check "a device step-up with a bad signature is refused (401)" [ "$(http_code)" = 401 ]

info "4/4 the admin surfaces and the per-account mandate the bridge enforces"
ADMIN_JWT="$(admin_jwt)"
amfa="$(bridge_api GET "/admin/accounts/$HOLDER/mfa" "$ADMIN_JWT")"
check_jq "GET /admin/accounts/{holder}/mfa: the factor summary shows TOTP and the device key, no secrets" \
  '.account_id != null and .totp_enrolled == true and (.device_keys | length) >= 1 and (.device_keys[0] | has("secret") | not)' "$amfa"
# Mandate MFA for the holder. The change signs the account out: its auth epoch moves to this second.
pol="$(bridge_api PUT "/admin/accounts/$HOLDER/mfa-policy" "$ADMIN_JWT" '{"required":true}')"
check "PUT /admin/accounts/{holder}/mfa-policy {required:true} succeeds" [ "$(http_code)" = 200 ]
MANDATED=1
check_jq "the mandate response reports required=true" '.required == true' "$pol"
# The epoch is inclusive: a token issued in the same second as the change is revoked with the older ones
# (fail closed), so the next sign-in has to fall in a later second.
sleep 2
bridge_api GET /mfa/status "$HJWT_MFA" >/dev/null 2>&1 || true
check "the mandate signed the holder out: the multi-factor token from part 2 is revoked (401)" [ "$(http_code)" = 401 ]
# A fresh single-factor session is now refused from a protected route…
HJWT3="$(bridge_login "$HOLDER" "$IMPALA_HOLDER_PASSWORD")"
denied_body="$(bridge_api GET "/account?stellar_account_id=$HOLDER_G" "$HJWT3" || true)"
denied="$(http_code)"
check "a required-but-single-factor session is refused from a protected route (403)" [ "$denied" = 403 ]
check_jq "the refusal names the mfa_required code (the dashboard and the app prompt for a step-up)" \
  '(.error.code // "") == "mfa_required"' "$denied_body"
check_jq "GET /mfa/status still answers that session (the way out is never locked): required, not satisfied" \
  '.required == true and .satisfied == false and .mfa != true' "$(status_of "$HJWT3")"
# …and a TOTP code is good once: the code that stepped the first session up is refused now.
replayed="$(bridge_api POST /mfa/step-up "$HJWT3" "$(jq -cn --arg c "$CODE" '{mfa_type:"totp", code:$c}')" || true)"
replay_code="$(http_code)"; leaked=0; printf '%s' "$replayed" | grep -q 'temporal_token' && leaked=1
check "the TOTP code used in part 2 is refused when presented again ($replay_code; a code is single-use), and no token is issued" [ "$replay_code" != 200 -a "$leaked" = 0 ]
# …until it steps up: here with the phone's device key, over a fresh challenge.
ch4="$(bridge_api POST /mfa/challenge "$HJWT3" '{}' | jq -r '.challenge')"
python3 "$MFA" device-message "$HOLDER" 2 "$ch4" > "$WORK/stepup3.bin"
STEPUP3_SIG="$(openssl dgst -sha256 -sign "$WORK/dev.pem" "$WORK/stepup3.bin" | bin_to_hex)"
stepup3="$(bridge_api POST /mfa/step-up "$HJWT3" "$(jq -cn --arg c "$ch4" --arg k "$KEY_ID" --arg s "$STEPUP3_SIG" \
  '{mfa_type:"device", challenge:$c, key_id:$k, device_signature:$s}')")"
check_jq "the device-key step-up under the mandate succeeds (amr: pwd + dev + mfa)" \
  '.success == true and (.amr | index("dev")) != null and (.amr | index("mfa")) != null' "$stepup3"
HJWT3_MFA="$(printf '%s' "$stepup3" | jq -r '.temporal_token // empty')"
[ -n "$HJWT3_MFA" ] || die "step-up under the mandate returned no token"
bridge_api GET "/account?stellar_account_id=$HOLDER_G" "$HJWT3_MFA" >/dev/null || true
check "after stepping up, the same account reaches the protected route (200)" [ "$(http_code)" = 200 ]
# Recovery: an admin revokes the lost device key.
bridge_api DELETE "/admin/accounts/$HOLDER/mfa/device-keys/$KEY_ID" "$ADMIN_JWT" >/dev/null || true
check "admin device-key recovery delete succeeds (200)" [ "$(http_code)" = 200 ]
[ "$(http_code)" = 200 ] && KEY_LIVE=0
# The event trail carries the factor changes (handles and the boolean only; never key bytes or a secret).
events="$(bridge_api GET '/admin/events?since=0&limit=500' "$ADMIN_JWT")"
check_jq "event feed: mfa.device_key_registered / _revoked / policy_changed, with no secret or key bytes in any payload" \
  '([.events[] | select(.event_type=="mfa.device_key_registered")] | length) >= 1
   and ([.events[] | select(.event_type=="mfa.device_key_revoked")] | length) >= 1
   and ([.events[] | select(.event_type=="mfa.policy_changed")] | length) >= 1
   and ([.events[] | select(.event_type | startswith("mfa.")) | .payload | tostring | test("secret|[0-9a-f]{130}")] | any | not)' "$events"
# Leave the holder as we found it: lift the mandate (the exit trap does the same after a failure).
bridge_api PUT "/admin/accounts/$HOLDER/mfa-policy" "$ADMIN_JWT" '{"required":false}' >/dev/null || true
check "the holder's MFA mandate is lifted again (state restored for later runs)" [ "$(http_code)" = 200 ]
[ "$(http_code)" = 200 ] && MANDATED=0

finish_scenario scenario-14-mfa "$(jq -cn --arg h "$HOLDER" --arg k "$KEY_ID" \
  --argjson s1 "$(printf '%s' "$stepup" | jq -c '{amr, mfa: ((.amr | index("mfa")) != null)}')" \
  '{holder:$h, device_key_id:$k, stepped_up:$s1,
    factors_demonstrated:["pwd","otp","dev"], mandate_enforced:true, recovery:true}')" "$t0"
