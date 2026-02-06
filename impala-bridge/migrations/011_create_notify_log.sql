-- Create notify_log table for tracking notification delivery events
CREATE TABLE IF NOT EXISTS notify_log (
    event_id BIGSERIAL PRIMARY KEY,
    notify_id INTEGER REFERENCES notify(id),
    notify_type VARCHAR(50),
    service_id VARCHAR(255),
    service_response TEXT,
    result VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on notify_id for faster lookups by notification
CREATE INDEX IF NOT EXISTS idx_notify_log_notify_id ON notify_log(notify_id);
