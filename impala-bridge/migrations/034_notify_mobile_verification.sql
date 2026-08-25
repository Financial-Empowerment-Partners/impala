-- SMS notification enrollment verification.
--
-- A phone number added for notifications must be confirmed by the recipient
-- before the bridge delivers to it. Enforcement lives in the dispatch query
-- (`notifications::dispatch_event`), which skips SMS targets whose
-- `mobile_verified_at` is NULL — so an unconfirmed number is inert rather
-- than merely flagged.

ALTER TABLE notify ADD COLUMN IF NOT EXISTS mobile_verified_at TIMESTAMP WITH TIME ZONE;

COMMENT ON COLUMN notify.mobile_verified_at IS
    'When the recipient confirmed the code sent to `mobile`. NULL means unverified: dispatch_event will not deliver SMS to this row.';

-- Changing the number invalidates the confirmation.
--
-- This is a trigger rather than handler logic because the invariant is
-- "verification always describes the number currently in the row". A handler
-- check covers the write paths that exist today; the trigger also covers the
-- ones added later, plus manual SQL during an incident. Getting this wrong
-- means notifications keep flowing to a number the account no longer lists.
CREATE OR REPLACE FUNCTION notify_reset_mobile_verification()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.mobile IS DISTINCT FROM OLD.mobile THEN
        NEW.mobile_verified_at := NULL;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_notify_reset_mobile_verification ON notify;
CREATE TRIGGER trg_notify_reset_mobile_verification
    BEFORE UPDATE ON notify
    FOR EACH ROW
    EXECUTE FUNCTION notify_reset_mobile_verification();

-- GRANDFATHERING (deliberate, and the one decision in this migration worth
-- reviewing): numbers already on file are marked verified so that applying
-- this migration does not silently stop SMS notifications for every existing
-- subscriber. Those numbers were accepted under the previous rules; treating
-- the deploy as a mass opt-out would be an outage, not a security fix.
--
-- To require everyone to re-confirm instead, drop this statement before
-- applying, or run afterwards:
--     UPDATE notify SET mobile_verified_at = NULL;
UPDATE notify
   SET mobile_verified_at = CURRENT_TIMESTAMP
 WHERE mobile IS NOT NULL
   AND mobile <> ''
   AND mobile_verified_at IS NULL;
