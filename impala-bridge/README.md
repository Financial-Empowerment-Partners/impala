# Impala bridge

The Payala impala bridge uses the Rust SDK to exercise the Horizon API or RPC API for
[accounts](https://developers.stellar.org/docs/data/apis/horizon/api-reference/resources/accounts), 
[assets](https://developers.stellar.org/docs/data/apis/horizon/api-reference/resources/assets),
[payments](https://developers.stellar.org/docs/data/apis/horizon/api-reference/resources/payments),
and [transactions](https://developers.stellar.org/docs/data/apis/horizon/api-reference/resources/transactions).

In turn, the Payala API is invoked by the impala bridge to correlate payments and accounts
in a Payala program with the Stellar network.

## Setup

### Prerequisites
- Rust toolchain (1.70+)
- PostgreSQL database

### Environment Variables
Copy `.env.example` to `.env` and configure your database connection:
```bash
cp .env.example .env
```

Edit `.env` with your database credentials:
```
DATABASE_URL=postgresql://username:password@localhost:5432/impala
```

#### HashiCorp Vault Integration (Optional)
Impala supports unwrapping secrets protected by Vault's cubbyhole response wrapping.

**Environment Variables for Vault:**
```
VAULT_ADDR=https://vault.example.com:8200
DATABASE_URL_WRAPPED=s.bad1234567890abc  # Example wrapping token
```

**Usage:**
- If `DATABASE_URL_WRAPPED` is set, application will automatically unwrap the secret from Vault during initialization
- The unwrapped secret should contain a `database_url` field with db connection string
- If unwrapping fails, the application will exit with an error
- If `DATABASE_URL_WRAPPED` is not set, the application falls back to using `DATABASE_URL` directly

**Creating a Wrapped Secret in Vault:**
```bash
# Write your database URL to Vault and wrap the response
vault kv put -wrap-ttl=60s secret/database database_url="postgresql://user:pass@localhost/impala"

# Use the wrapping token in your environment
export DATABASE_URL_WRAPPED="s.bad1234567890abc"
export VAULT_ADDR="https://vault.example.com:8200"
```

**The `box_unwrap` Function:**
The `box_unwrap(wrapping_token: &str)` function encapsulates the unwrapping process:
- Takes a one-time wrapping token as input
- Connects to Vault using the `VAULT_ADDR` environment variable
- Makes a POST request to `/v1/sys/wrapping/unwrap`
- Returns the unwrapped secret data as `serde_json::Value`
- Handles errors gracefully with detailed error messages

### Database Setup
Run the SQL migrations to create the required tables:
```bash
psql -d impala -f migrations/001_create_impala_account.sql
psql -d impala -f migrations/002_create_impala_auth.sql
psql -d impala -f migrations/003_create_impala_schema.sql
```

Or run all migrations at once:
```bash
for migration in migrations/*.sql; do
  psql -d impala -f "$migration"
done
```

### Running the Application
```bash
cargo build
cargo run
```

The server will start on `http://0.0.0.0:8080`

## API Endpoints

### GET /
Health check endpoint.

**Response:**
```
Hello, World!
```

### GET /version
Returns application version information, including database schema version.

**Response:**
```json
{
  "name": "impala-bridge",
  "version": "0.0.0",
  "build_date": "2026-01-30 12:34:56 UTC",
  "rustc_version": "rustc 1.75.0",
  "schema_version": "1.0.3"
}
```

**Note:** The `schema_version` field will be `null` if the `impala_schema` table hasn't been created yet.

### POST /account
Creates a new account linking Stellar and Payala account information.

**Request Body:**
```json
{
  "stellar_account_id": "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "payala_account_id": "payala_12345",
  "first_name": "John",
  "middle_name": "Q",
  "last_name": "Doe",
  "nickname": "johnd",
  "affiliation": "Company XYZ",
  "gender": "male"
}
```

**Required Fields:**
- `stellar_account_id` (string): Stellar account public key
- `payala_account_id` (string): Payala account identifier
- `first_name` (string): First name
- `last_name` (string): Last name

**Optional Fields:**
- `middle_name` (string): Middle name
- `nickname` (string): Nickname or preferred name
- `affiliation` (string): Organization or affiliation
- `gender` (string): Gender

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Account created successfully"
}
```

**Error Response (500 Internal Server Error):**
Returns when database operation fails.

### GET /account
Retrieves account information by Stellar account ID.

**Query Parameters:**
- `stellar_account_id` (string, required): Stellar account public key to look up

**Example Request:**
```bash
curl -X GET "http://localhost:8080/account?stellar_account_id=GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
```

**Success Response (200 OK):**
```json
{
  "payala_account_id": "payala_12345",
  "first_name": "John",
  "middle_name": "Q",
  "last_name": "Doe",
  "nickname": "johnd",
  "affiliation": "Company XYZ",
  "gender": "male"
}
```

**Note:** Fields that are null in the database will be omitted from the response or returned as null.

**Error Responses:**
- **404 Not Found:** No account found with the provided stellar_account_id
- **500 Internal Server Error:** Database operation failed

### PUT /account
Updates an existing account. Uses either `stellar_account_id` or `payala_account_id` to identify the record to update.

**Request Body:**
All fields are optional. At least one identifier (`stellar_account_id` or `payala_account_id`) must be provided.

```json
{
  "stellar_account_id": "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "first_name": "Jane",
  "nickname": "janey"
}
```

**Identifier Fields (at least one required):**
- `stellar_account_id` (string): Stellar account public key - if provided and not used as identifier, will be updated
- `payala_account_id` (string): Payala account identifier - if provided and not used as identifier, will be updated

**Optional Update Fields:**
- `first_name` (string): First name
- `middle_name` (string): Middle name
- `last_name` (string): Last name
- `nickname` (string): Nickname or preferred name
- `affiliation` (string): Organization or affiliation
- `gender` (string): Gender

**Behavior:**
- If `stellar_account_id` is provided, it will be used to identify the record (WHERE clause)
- If only `payala_account_id` is provided, it will be used to identify the record
- Any other provided fields will be updated
- If an identifier is provided but also appears in another field, it can be updated

**Example Requests:**

Update using stellar_account_id as identifier:
```bash
curl -X PUT http://localhost:8080/account \
  -H "Content-Type: application/json" \
  -d '{
    "stellar_account_id": "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "first_name": "Jane",
    "nickname": "janey"
  }'
```

Update using payala_account_id as identifier:
```bash
curl -X PUT http://localhost:8080/account \
  -H "Content-Type: application/json" \
  -d '{
    "payala_account_id": "payala_12345",
    "affiliation": "New Company",
    "gender": "female"
  }'
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Account updated successfully",
  "rows_affected": 1
}
```

**Error Responses:**

When no identifier provided (200 OK with success: false):
```json
{
  "success": false,
  "message": "Either stellar_account_id or payala_account_id must be provided",
  "rows_affected": 0
}
```

When no fields to update (200 OK with success: false):
```json
{
  "success": false,
  "message": "No fields provided to update",
  "rows_affected": 0
}
```

When account not found (200 OK with success: false):
```json
{
  "success": false,
  "message": "No account found with the provided identifier",
  "rows_affected": 0
}
```

**500 Internal Server Error:** Database operation failed

