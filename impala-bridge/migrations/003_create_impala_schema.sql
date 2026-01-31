-- Create impala_schema table to track database schema version
CREATE TABLE IF NOT EXISTS impala_schema (
    id SERIAL PRIMARY KEY,
    current_version VARCHAR(50) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    description TEXT
);

-- Insert initial schema version
INSERT INTO impala_schema (current_version, description)
VALUES ('1.0.0', 'Initial schema with impala_account and impala_auth tables')
ON CONFLICT DO NOTHING;

-- Create trigger to automatically update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_impala_schema_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_impala_schema_timestamp
    BEFORE UPDATE ON impala_schema
    FOR EACH ROW
    EXECUTE FUNCTION update_impala_schema_timestamp();
