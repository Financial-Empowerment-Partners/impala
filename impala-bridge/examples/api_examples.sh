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
