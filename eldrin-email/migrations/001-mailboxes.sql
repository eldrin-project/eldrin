CREATE TABLE connected_mailboxes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  email_address TEXT NOT NULL,
  display_name TEXT,
  access_token_encrypted TEXT NOT NULL,
  refresh_token_encrypted TEXT NOT NULL,
  token_expires_at INTEGER NOT NULL,
  last_sync_at INTEGER,
  sync_status TEXT NOT NULL DEFAULT 'active',
  sync_depth TEXT NOT NULL DEFAULT 'metadata',
  sync_cursor TEXT,
  error_message TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX idx_mailboxes_user_id ON connected_mailboxes(user_id);
CREATE UNIQUE INDEX idx_mailboxes_provider_email ON connected_mailboxes(provider, email_address);
CREATE INDEX idx_mailboxes_sync_status ON connected_mailboxes(sync_status);
