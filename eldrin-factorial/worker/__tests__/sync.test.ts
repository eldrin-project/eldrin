import { describe, it, expect } from 'vitest';
import { syncEmployees } from '../services/sync';
import type { FactorialClient } from '../services/factorial-client';

function fakeClient(rows: unknown[]): FactorialClient {
  return { get: async () => ({ data: rows }) as any, getAll: async () => rows as any };
}

function fakeDb() {
  const upserts: any[] = [];
  const db: any = {
    insert: () => ({
      values: (v: any) => ({
        onConflictDoUpdate: () => { upserts.push(v); return Promise.resolve(); },
      }),
    }),
    _upserts: upserts,
  };
  return db;
}

describe('syncEmployees', () => {
  it('upserts each employee mapped from the validated Factorial payload shape', async () => {
    const db = fakeDb();
    // Validated employee fields: id, first_name, last_name, full_name, email.
    // No top-level job_title/team_id, so those map to null.
    const client = fakeClient([
      { id: 10, first_name: 'Ada', last_name: 'Lovelace', full_name: 'Ada Lovelace', email: 'ada@x.io', manager_id: 2 },
    ]);
    const count = await syncEmployees(db, client);
    expect(count).toBe(1);
    expect(db._upserts[0]).toMatchObject({
      factorialId: '10', fullName: 'Ada Lovelace', email: 'ada@x.io', jobTitle: null, teamId: null,
    });
    expect(typeof db._upserts[0].syncedAt).toBe('number');
    expect(typeof db._upserts[0].rawJson).toBe('string');
  });

  it('derives full_name from first/last when full_name is absent', async () => {
    const db = fakeDb();
    const client = fakeClient([{ id: 11, first_name: 'Grace', last_name: 'Hopper', email: 'grace@x.io' }]);
    await syncEmployees(db, client);
    expect(db._upserts[0]).toMatchObject({ factorialId: '11', fullName: 'Grace Hopper' });
  });
});
