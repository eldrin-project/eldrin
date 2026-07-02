-- Phase 6: Email Templates with merge field support

CREATE TABLE email_templates (
  id          TEXT    PRIMARY KEY,
  name        TEXT    NOT NULL,
  subject     TEXT    NOT NULL,
  body_html   TEXT    NOT NULL,
  body_text   TEXT,
  merge_fields TEXT,                                -- JSON array of detected field names
  category    TEXT,
  is_shared   INTEGER NOT NULL DEFAULT 0,
  usage_count INTEGER NOT NULL DEFAULT 0,
  owner_id    TEXT    NOT NULL,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

CREATE INDEX idx_templates_owner    ON email_templates(owner_id);
CREATE INDEX idx_templates_shared   ON email_templates(is_shared);
CREATE INDEX idx_templates_category ON email_templates(category);
