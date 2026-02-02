-- Stored procedure to log which tx_id fields are present on insert/update
CREATE OR REPLACE FUNCTION log_transaction_tx_ids()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.stellar_tx_id IS NOT NULL THEN
        RAISE LOG 'transaction % has stellar_tx_id: %', NEW.btxid, NEW.stellar_tx_id;
    END IF;

    IF NEW.payala_tx_id IS NOT NULL THEN
        RAISE LOG 'transaction % has payala_tx_id: %', NEW.btxid, NEW.payala_tx_id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_transaction_log_tx_ids
    AFTER INSERT OR UPDATE ON transaction
    FOR EACH ROW
    EXECUTE FUNCTION log_transaction_tx_ids();
