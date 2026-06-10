#!/bin/bash
# Example API calls for impala-bridge

BASE_URL="http://localhost:8080"

echo "=== Testing GET / ==="
curl -X GET "$BASE_URL/"
echo -e "\n"

echo "=== Testing GET /version ==="
curl -X GET "$BASE_URL/version" | jq .
echo -e "\n"

echo "=== Testing POST /account ==="
curl -X POST "$BASE_URL/account" \
  -H "Content-Type: application/json" \
  -d '{
    "stellar_account_id": "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "payala_account_id": "payala_12345",
    "first_name": "John",
    "middle_name": "Q",
    "last_name": "Doe",
    "nickname": "johnd",
    "affiliation": "Company XYZ",
    "gender": "male"
  }' | jq .
echo -e "\n"

echo "=== Testing POST /account (minimal fields) ==="
curl -X POST "$BASE_URL/account" \
  -H "Content-Type: application/json" \
  -d '{
    "stellar_account_id": "GYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
    "payala_account_id": "payala_67890",
    "first_name": "Jane",
    "last_name": "Smith"
  }' | jq .
echo -e "\n"

echo "=== Testing GET /account ==="
curl -X GET "$BASE_URL/account?stellar_account_id=GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" | jq .
echo -e "\n"

echo "=== Testing GET /account (not found) ==="
curl -X GET "$BASE_URL/account?stellar_account_id=GZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ" -w "\nHTTP Status: %{http_code}\n"
echo -e "\n"

echo "=== Testing PUT /account (update using stellar_account_id) ==="
curl -X PUT "$BASE_URL/account" \
  -H "Content-Type: application/json" \
  -d '{
    "stellar_account_id": "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "first_name": "John",
    "nickname": "johnny",
    "affiliation": "Updated Company"
  }' | jq .
echo -e "\n"

echo "=== Testing PUT /account (update using payala_account_id) ==="
curl -X PUT "$BASE_URL/account" \
  -H "Content-Type: application/json" \
  -d '{
    "payala_account_id": "payala_12345",
    "gender": "non-binary",
    "middle_name": "R"
  }' | jq .
echo -e "\n"

echo "=== Testing PUT /account (no identifier - error) ==="
curl -X PUT "$BASE_URL/account" \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "Test"
  }' | jq .
echo -e "\n"

echo "=== Testing PUT /account (account not found) ==="
curl -X PUT "$BASE_URL/account" \
  -H "Content-Type: application/json" \
  -d '{
    "stellar_account_id": "GZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
    "first_name": "Test"
  }' | jq .
echo -e "\n"

# ── Token exchange: Google / GitHub / card ──────────────────────────────────
# All exchange endpoints return the same TokenResponse shape as POST /token:
#   {success, message, refresh_token, temporal_token}
# Use the refresh_token with POST /token {"refresh_token": ...} to mint new
# temporal tokens; the temporal token goes in the Authorization header.

echo "=== Google config (GET /auth/google/config) ==="
# {enabled:false} when GOOGLE_CLIENT_ID is unset; {enabled:true, client_id} otherwise.
curl -X GET "$BASE_URL/auth/google/config" | jq .
echo -e "\n"

echo "=== Google token exchange (POST /auth/google) ==="
# id_token: a Google ID token whose aud matches GOOGLE_CLIENT_ID.
# Account id = verified email (lowercased), else google:{sub}.
curl -X POST "$BASE_URL/auth/google" \
  -H "Content-Type: application/json" \
  -d '{"id_token": "'"$GOOGLE_ID_TOKEN"'"}' | jq .
echo -e "\n"

echo "=== GitHub token exchange (POST /auth/github) ==="
# Requires GITHUB_AUTH_ENABLED=true on the bridge (400 otherwise).
# access_token: a GitHub OAuth/device-flow token; verified via GET /user.
# Account id = github:{numeric user id}.
curl -X POST "$BASE_URL/auth/github" \
  -H "Content-Type: application/json" \
  -d '{"access_token": "'"$GITHUB_ACCESS_TOKEN"'"}' | jq .
echo -e "\n"

echo "=== Card challenge (POST /auth/card/challenge) ==="
# card_id: as registered via POST /card (8-32 hex chars). Issued
# unconditionally (never reveals whether a card is registered), single-use,
# 60s TTL. Returns {success, challenge: <64 hex>, expires_in: 60}.
CARD_ID="a1b2c3d4e5f60718"
CHALLENGE=$(curl -s -X POST "$BASE_URL/auth/card/challenge" \
  -H "Content-Type: application/json" \
  -d '{"card_id": "'"$CARD_ID"'"}' | jq -r .challenge)
echo "challenge: $CHALLENGE"
echo -e "\n"

echo "=== Card token exchange (POST /auth/card) ==="
# Have the card sign the RAW challenge bytes (hex-decode first) via
# INS_SIGN_AUTH (ImpalaSDK.signAuthChallenge). The card signs ECDSA-SHA256
# over "IMPALA-AUTH:" || accountId(16) || challenge; send the DER signature
# hex-encoded. Any failure (bad signature, replayed/expired challenge,
# unknown card) returns the same generic 401 and counts toward lockout.
curl -X POST "$BASE_URL/auth/card" \
  -H "Content-Type: application/json" \
  -d '{"card_id": "'"$CARD_ID"'", "signature": "'"$CARD_SIGNATURE_HEX"'"}' | jq .
echo -e "\n"

# ── Admin webhook event feed ────────────────────────────────────────────────
# All /admin/* routes require a TEMPORAL token whose subject is in
# ADMIN_ACCOUNT_IDS (the is_admin claim is stamped server-side at issuance).
# Obtain one via POST /token, then:
#   ADMIN_TOKEN="<temporal token for an admin account>"

echo "=== Register an admin webhook (POST /admin/webhooks) ==="
# Returns {id, url, secret}; the secret is shown ONCE — store it to verify signatures.
# NOTE: validate_callback_url blocks localhost/private IPs, so use a public URL.
curl -X POST "$BASE_URL/admin/webhooks" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://webhook.example.com/impala",
    "event_types": ["account.created", "account.updated", "transaction.created"]
  }' | jq .
echo -e "\n"

echo "=== List admin webhooks (GET /admin/webhooks) — secret never returned ==="
curl -X GET "$BASE_URL/admin/webhooks" -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
echo -e "\n"

echo "=== Send a test event to webhook 1 (POST /admin/webhooks/1/test) ==="
curl -X POST "$BASE_URL/admin/webhooks/1/test" -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
echo -e "\n"

echo "=== Pull/replay the event feed (GET /admin/events?since=0&limit=50) ==="
curl -X GET "$BASE_URL/admin/events?since=0&limit=50" -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
echo -e "\n"

echo "=== Delete a webhook (DELETE /admin/webhooks/1) ==="
curl -X DELETE "$BASE_URL/admin/webhooks/1" -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
echo -e "\n"

# Receiver-side signature verification (pseudocode):
#   expected = "sha256=" + hex(HMAC_SHA256(secret, X-Impala-Timestamp + "." + raw_body))
#   reject unless constant_time_eq(expected, X-Impala-Signature)
#   reject if abs(now - X-Impala-Timestamp) > 300  # replay window

# ── Tokens: strict refresh rotation + reuse detection ───────────────────────
# POST /token {username, password} now returns BOTH tokens (the temporal one
# saves a round trip). Refresh tokens are SINGLE-USE: every refresh burns the
# presented token and returns a replacement pair. Reusing a burned refresh
# token revokes the entire token family (theft response) — store the new
# refresh_token from every /token response.

echo "=== Login (POST /token) — returns refresh + temporal ==="
PAIR1=$(curl -s -X POST "$BASE_URL/token" \
  -H "Content-Type: application/json" \
  -d '{"username": "payala_12345", "password": "correct horse battery"}')
R1=$(echo "$PAIR1" | jq -r .refresh_token)
echo "$PAIR1" | jq '{success, message}'
echo -e "\n"

echo "=== Refresh (POST /token {refresh_token}) — rotates the refresh token ==="
PAIR2=$(curl -s -X POST "$BASE_URL/token" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "'"$R1"'"}')
R2=$(echo "$PAIR2" | jq -r .refresh_token)
TEMPORAL=$(echo "$PAIR2" | jq -r .temporal_token)
echo "$PAIR2" | jq '{success, message}'
echo -e "\n"

echo "=== Reusing the burned refresh token => 401 AND the family is revoked ==="
curl -s -X POST "$BASE_URL/token" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "'"$R1"'"}' -o /dev/null -w "HTTP Status: %{http_code} (expected 401)\n"
curl -s -X POST "$BASE_URL/token" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "'"$R2"'"}' -o /dev/null -w "HTTP Status: %{http_code} (expected 401 — descendant revoked too)\n"
echo -e "\n"

echo "=== Logout everywhere (POST /logout/all) ==="
# Bumps the account's auth epoch: every refresh/temporal token issued before
# this moment — on any device — and every browser session is rejected.
curl -s -X POST "$BASE_URL/logout/all" \
  -H "Authorization: Bearer $TEMPORAL" | jq .
echo -e "\n"

# JWT secret rotation (zero downtime): deploy with
#   JWT_SECRET=<new>  JWT_SECRET_PREVIOUS=<old>
# New tokens are signed with the new secret (kid header selects the key);
# tokens signed with the old secret keep verifying until they expire
# (<= 14 days), then unset JWT_SECRET_PREVIOUS.

# ── Browser cookie sessions + CSRF (the impala-ui flow) ─────────────────────
# POST /session/login sets an HttpOnly cookie (__Host-impala_session with
# SESSION_COOKIE_SECURE=true, impala_session on plain-HTTP dev) and returns a
# CSRF token. Cookie-authenticated mutations REQUIRE X-CSRF-Token; bearer
# requests are exempt (no ambient credential). GET /session/me re-fetches the
# CSRF token after a page reload.

COOKIES=/tmp/impala_cookies
echo "=== Session login (POST /session/login) ==="
SESSION=$(curl -s -c "$COOKIES" -X POST "$BASE_URL/session/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "payala_12345", "password": "correct horse battery"}')
CSRF=$(echo "$SESSION" | jq -r .csrf_token)
echo "$SESSION" | jq '{success, account_id, is_admin}'
echo -e "\n"

echo "=== Cookie GET (no CSRF needed) ==="
curl -s -b "$COOKIES" "$BASE_URL/session/me" | jq '{success, account_id}'
echo -e "\n"

echo "=== Cookie mutation WITHOUT X-CSRF-Token => 403 ==="
curl -s -b "$COOKIES" -X POST "$BASE_URL/notify" \
  -H "Content-Type: application/json" \
  -d '{"account_id": "payala_12345", "medium": "email", "email": "a@b.cd"}' \
  -o /dev/null -w "HTTP Status: %{http_code} (expected 403)\n"
echo -e "\n"

echo "=== Cookie mutation WITH X-CSRF-Token => passes CSRF ==="
curl -s -b "$COOKIES" -X POST "$BASE_URL/notify" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF" \
  -d '{"account_id": "payala_12345", "medium": "email", "email": "a@b.cd"}' | jq '{success, message}'
echo -e "\n"

echo "=== Session logout (POST /session/logout — CSRF required) ==="
curl -s -b "$COOKIES" -X POST "$BASE_URL/session/logout" \
  -H "X-CSRF-Token: $CSRF" | jq .
echo -e "\n"

# Okta browser flow: POST /auth/okta {okta_token, cookie_mode: true} returns
# the same session response (+ Set-Cookie) instead of JWTs.

# GitHub server-side code exchange: POST /auth/github {code, redirect_uri}
# exchanges the OAuth authorization code at github.com using the bridge's
# GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET (the secret never ships in an app
# binary); {access_token} stays supported for older clients. The response
# adds optional login/display_name fields.
