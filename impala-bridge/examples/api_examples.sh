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
