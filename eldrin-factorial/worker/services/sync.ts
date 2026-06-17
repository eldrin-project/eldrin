import type { Database } from '../db';
import { employees, projects, syncState } from '../db';
import type { FactorialClient } from './factorial-client';
import { createFactorialClient } from './factorial-client';
import { generateId, now } from '../utils';

// Validated employee fields: id, first_name, last_name, full_name, email, manager_id.
// job_title / team_id are NOT top-level fields in the 2026-04-01 employees resource.
interface RawEmployee {
  id: number | string;
  first_name?: string;
  last_name?: string;
  full_name?: string;
  email?: string;
  job_title?: string;      // not present today; mapped if it ever appears
  team_id?: number | string;
}
interface RawProject { id: number | string; name?: string; status?: string }

const asStr = (v: unknown): string | null => (v === undefined || v === null ? null : String(v));

function employeeFullName(r: RawEmployee): string | null {
  if (r.full_name) return r.full_name;
  const joined = [r.first_name, r.last_name].filter(Boolean).join(' ').trim();
  return joined.length > 0 ? joined : null;
}

export async function syncEmployees(db: Database, client: FactorialClient): Promise<number> {
  const rows = await client.getAll<RawEmployee>('/employees/employees?only_active=true');
  const ts = now();
  for (const r of rows) {
    const fields = {
      fullName: employeeFullName(r),
      email: r.email ?? null,
      jobTitle: r.job_title ?? null,
      teamId: asStr(r.team_id),
      rawJson: JSON.stringify(r),
      syncedAt: ts,
    };
    await db.insert(employees).values({
      id: generateId(),
      factorialId: String(r.id),
      ...fields,
    }).onConflictDoUpdate({
      target: employees.factorialId,
      set: fields,
    });
  }
  return rows.length;
}

export async function syncProjects(db: Database, client: FactorialClient): Promise<number> {
  const rows = await client.getAll<RawProject>('/project_management/projects');
  const ts = now();
  for (const r of rows) {
    const fields = {
      name: r.name ?? null,
      status: r.status ?? null,
      rawJson: JSON.stringify(r),
      syncedAt: ts,
    };
    await db.insert(projects).values({
      id: generateId(),
      factorialId: String(r.id),
      ...fields,
    }).onConflictDoUpdate({
      target: projects.factorialId,
      set: fields,
    });
  }
  return rows.length;
}

async function recordState(db: Database, resource: string, status: 'ok' | 'error', error: string | null) {
  await db.insert(syncState).values({
    id: generateId(), resource, lastSyncedAt: now(), lastStatus: status, lastError: error,
  }).onConflictDoUpdate({
    target: syncState.resource,
    set: { lastSyncedAt: now(), lastStatus: status, lastError: error },
  });
}

export async function runSync(db: Database, env: Env): Promise<{ employees: number; projects: number }> {
  const client = createFactorialClient(env);

  let empCount = 0;
  try {
    empCount = await syncEmployees(db, client);
    await recordState(db, 'employees', 'ok', null);
  } catch (e) {
    await recordState(db, 'employees', 'error', e instanceof Error ? e.message : String(e));
    throw e;
  }

  let projCount = 0;
  try {
    projCount = await syncProjects(db, client);
    await recordState(db, 'projects', 'ok', null);
  } catch (e) {
    await recordState(db, 'projects', 'error', e instanceof Error ? e.message : String(e));
    throw e;
  }

  return { employees: empCount, projects: projCount };
}
