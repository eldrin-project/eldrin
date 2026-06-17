CREATE TABLE IF NOT EXISTS employees (
  id TEXT PRIMARY KEY,
  factorial_id TEXT NOT NULL,
  full_name TEXT,
  email TEXT,
  job_title TEXT,
  team_id TEXT,
  raw_json TEXT,
  synced_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_employees_factorial_id ON employees (factorial_id);

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  factorial_id TEXT NOT NULL,
  name TEXT,
  status TEXT,
  raw_json TEXT,
  synced_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_factorial_id ON projects (factorial_id);

CREATE TABLE IF NOT EXISTS sync_state (
  id TEXT PRIMARY KEY,
  resource TEXT NOT NULL,
  last_synced_at INTEGER,
  last_status TEXT,
  last_error TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sync_state_resource ON sync_state (resource);
