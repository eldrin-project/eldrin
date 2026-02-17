CREATE TABLE email_threads (
  id TEXT PRIMARY KEY,
  mailbox_id TEXT NOT NULL REFERENCES connected_mailboxes(id) ON DELETE CASCADE,
  provider_thread_id TEXT NOT NULL,
  subject TEXT,
  last_message_at INTEGER NOT NULL,
  message_count INTEGER NOT NULL DEFAULT 1,
  is_read INTEGER NOT NULL DEFAULT 0,
  is_starred INTEGER NOT NULL DEFAULT 0,
  is_archived INTEGER NOT NULL DEFAULT 0,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX idx_threads_mailbox ON email_threads(mailbox_id);
CREATE INDEX idx_threads_last_message ON email_threads(mailbox_id, last_message_at);
CREATE UNIQUE INDEX idx_threads_provider ON email_threads(mailbox_id, provider_thread_id);

CREATE TABLE emails (
  id TEXT PRIMARY KEY,
  thread_id TEXT NOT NULL REFERENCES email_threads(id) ON DELETE CASCADE,
  mailbox_id TEXT NOT NULL REFERENCES connected_mailboxes(id) ON DELETE CASCADE,
  provider_message_id TEXT NOT NULL,
  message_id TEXT NOT NULL UNIQUE,
  in_reply_to TEXT,
  from_address TEXT NOT NULL,
  from_name TEXT,
  to_addresses TEXT NOT NULL,
  cc_addresses TEXT,
  bcc_addresses TEXT,
  subject TEXT,
  body_text TEXT,
  body_html TEXT,
  snippet TEXT,
  has_attachments INTEGER NOT NULL DEFAULT 0,
  direction TEXT NOT NULL,
  sent_at INTEGER,
  received_at INTEGER NOT NULL,
  labels TEXT,
  is_read INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE INDEX idx_emails_thread ON emails(thread_id);
CREATE INDEX idx_emails_mailbox_received ON emails(mailbox_id, received_at);
CREATE INDEX idx_emails_from ON emails(from_address);
CREATE INDEX idx_emails_is_read ON emails(is_read);
