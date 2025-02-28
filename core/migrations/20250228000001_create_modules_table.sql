-- Create modules table
CREATE TABLE IF NOT EXISTS modules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    version VARCHAR(50) NOT NULL,
    description TEXT,
    author VARCHAR(255),
    is_core BOOLEAN NOT NULL DEFAULT FALSE,
    active BOOLEAN NOT NULL DEFAULT FALSE,
    path VARCHAR(255) NOT NULL,
    dependencies JSONB,
    repository VARCHAR(255),
    config JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_modules_name ON modules(name);
CREATE INDEX IF NOT EXISTS idx_modules_active ON modules(active);