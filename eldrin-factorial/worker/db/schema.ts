import { sqliteTable, text, integer, uniqueIndex } from 'drizzle-orm/sqlite-core';

export const employees = sqliteTable('employees', {
  id: text('id').primaryKey(),
  factorialId: text('factorial_id').notNull(),
  fullName: text('full_name'),
  email: text('email'),
  jobTitle: text('job_title'),
  teamId: text('team_id'),
  rawJson: text('raw_json'),
  syncedAt: integer('synced_at', { mode: 'number' }).notNull(),
}, (t) => [uniqueIndex('idx_employees_factorial_id').on(t.factorialId)]);

export const projects = sqliteTable('projects', {
  id: text('id').primaryKey(),
  factorialId: text('factorial_id').notNull(),
  name: text('name'),
  status: text('status'),
  rawJson: text('raw_json'),
  syncedAt: integer('synced_at', { mode: 'number' }).notNull(),
}, (t) => [uniqueIndex('idx_projects_factorial_id').on(t.factorialId)]);

export const syncState = sqliteTable('sync_state', {
  id: text('id').primaryKey(),
  resource: text('resource').notNull(), // 'employees' | 'projects'
  lastSyncedAt: integer('last_synced_at', { mode: 'number' }),
  lastStatus: text('last_status'),       // 'ok' | 'error'
  lastError: text('last_error'),
}, (t) => [uniqueIndex('idx_sync_state_resource').on(t.resource)]);
