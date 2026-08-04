-- Bind provider-side customer identifiers to local accounts.
--
-- OwlPay transfers are executed `on_behalf_of` a Harbor customer uuid
-- (`cus_...`). That identifier arrives in the request body, so without a
-- server-side binding any authenticated caller could name someone else's
-- customer record and move value against it — `require_owner` only proves the
-- caller owns the *Payala* account in the payload, not the OwlPay customer.
--
-- Binding is trust-on-first-use and exclusive in both directions: an account
-- claims at most one customer id per provider (uq index below is the PK), and
-- a customer id can never be claimed by a second account (uq_..._customer).
-- A conflicting claim is rejected at insert time rather than papered over, so
-- the race between two concurrent first-use attempts resolves in the DB.
CREATE TABLE IF NOT EXISTS exchange_customer (
    payala_account_id VARCHAR(64) NOT NULL REFERENCES impala_account(payala_account_id) ON DELETE CASCADE,
    provider VARCHAR(24) NOT NULL,
    -- Provider-issued customer identifier (OwlPay Harbor `cus_...`).
    provider_customer_id VARCHAR(128) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (payala_account_id, provider),
    CONSTRAINT chk_exchange_customer_provider CHECK (provider IN ('owlpay', 'changelly_crypto', 'changelly_fiat'))
);

-- One customer identifier belongs to exactly one account, forever.
CREATE UNIQUE INDEX IF NOT EXISTS uq_exchange_customer_customer
    ON exchange_customer(provider, provider_customer_id);

-- Reuse update_updated_at_column() defined in 002.
CREATE TRIGGER update_exchange_customer_updated_at
    BEFORE UPDATE ON exchange_customer
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
