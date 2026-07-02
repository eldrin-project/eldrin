-- Phase 8: Cross-app integration — add provenance columns to emails

ALTER TABLE emails ADD COLUMN related_app TEXT;
ALTER TABLE emails ADD COLUMN related_record_id TEXT;

CREATE INDEX IF NOT EXISTS idx_emails_related ON emails(related_app, related_record_id);
