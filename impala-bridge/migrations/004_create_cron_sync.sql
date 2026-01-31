CREATE TABLE IF NOT EXISTS cron_sync (
    id SERIAL PRIMARY KEY,
    callback_uri TEXT NOT NULL,
    callback_result JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION update_cron_sync_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_cron_sync_updated_at
    BEFORE UPDATE ON cron_sync
    FOR EACH ROW
    EXECUTE FUNCTION update_cron_sync_updated_at();
