import { drizzle as drizzleD1 } from 'drizzle-orm/d1';
import * as schema from './schema';

export * from './schema';
export { schema };

export type Database = ReturnType<typeof createDb>;

export function createDb(env: Record<string, unknown>) {
  const d1 = env.DB as D1Database;
  return drizzleD1(d1, { schema });
}
