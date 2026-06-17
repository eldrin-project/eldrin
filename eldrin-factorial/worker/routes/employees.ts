import { Hono } from 'hono';
import { asc } from 'drizzle-orm';
import { employees, type Database } from '../db';

type Variables = { db: Database; userId: string };

export const employeesRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

employeesRoutes.get('/api/employees', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const db = c.get('db');
  const rows = await db.query.employees.findMany({ orderBy: [asc(employees.fullName)] });
  return c.json({ employees: rows });
});
