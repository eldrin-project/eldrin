-- Phase 5: Add status and scheduled_at columns for scheduled sending
ALTER TABLE emails ADD COLUMN status TEXT NOT NULL DEFAULT 'sent';
ALTER TABLE emails ADD COLUMN scheduled_at INTEGER;

CREATE INDEX idx_emails_status ON emails(status, scheduled_at);
