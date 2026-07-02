-- Phase 7: Email open & click tracking

CREATE TABLE IF NOT EXISTS email_tracking (
  id TEXT PRIMARY KEY,
  email_id TEXT NOT NULL,
  tracking_id TEXT UNIQUE NOT NULL,
  open_count INTEGER NOT NULL DEFAULT 0,
  click_count INTEGER NOT NULL DEFAULT 0,
  first_opened_at INTEGER,
  last_opened_at INTEGER,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tracking_email ON email_tracking(email_id);
CREATE INDEX IF NOT EXISTS idx_tracking_tracking_id ON email_tracking(tracking_id);

CREATE TABLE IF NOT EXISTS tracking_events (
  id TEXT PRIMARY KEY,
  tracking_id TEXT NOT NULL,
  event_type TEXT NOT NULL,  -- 'open' | 'click'
  url TEXT,                  -- clicked URL (NULL for opens)
  user_agent TEXT,
  ip_address TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tracking_events_tracking ON tracking_events(tracking_id);
