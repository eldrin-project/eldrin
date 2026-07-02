/**
 * Template CRUD API routes.
 *
 * Users can create, list, update, and delete email templates.
 * Templates can be personal or shared (visible to all users).
 * Merge fields are auto-detected from subject + body on create/update.
 */

import { Hono } from 'hono';
import { eq, and, or, desc, like, sql } from 'drizzle-orm';
import { emailTemplates, type Database } from '../db';
import { generateId, now } from '../utils';
import { extractMergeFields, resolveMergeFields, getSampleContext } from '../services/merge-fields';

type Variables = { db: Database; userId: string };

export const templateRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

// ── GET /api/templates — list templates (own + shared) ──────────────────────

templateRoutes.get('/api/templates', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const db = c.get('db');
  const category = c.req.query('category') || '';
  const search = c.req.query('search') || '';

  const conditions = [
    or(
      eq(emailTemplates.ownerId, userId),
      eq(emailTemplates.isShared, true),
    ),
  ];

  if (category) {
    conditions.push(eq(emailTemplates.category, category));
  }
  if (search) {
    conditions.push(
      or(
        like(emailTemplates.name, `%${search}%`),
        like(emailTemplates.subject, `%${search}%`),
      ),
    );
  }

  const templates = await db
    .select()
    .from(emailTemplates)
    .where(and(...conditions))
    .orderBy(desc(emailTemplates.updatedAt));

  return c.json({
    templates: templates.map((t) => ({
      id: t.id,
      name: t.name,
      subject: t.subject,
      category: t.category,
      isShared: t.isShared,
      usageCount: t.usageCount,
      mergeFields: t.mergeFields ? JSON.parse(t.mergeFields) : [],
      ownerId: t.ownerId,
      isOwner: t.ownerId === userId,
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
    })),
  });
});

// ── GET /api/templates/:id — get single template ────────────────────────────

templateRoutes.get('/api/templates/:id', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const db = c.get('db');
  const id = c.req.param('id');

  const template = await db.query.emailTemplates.findFirst({
    where: and(
      eq(emailTemplates.id, id),
      or(
        eq(emailTemplates.ownerId, userId),
        eq(emailTemplates.isShared, true),
      ),
    ),
  });

  if (!template) return c.json({ error: 'Template not found' }, 404);

  return c.json({
    template: {
      ...template,
      mergeFields: template.mergeFields ? JSON.parse(template.mergeFields) : [],
      isOwner: template.ownerId === userId,
    },
  });
});

// ── POST /api/templates — create template ───────────────────────────────────

templateRoutes.post('/api/templates', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const db = c.get('db');
  const body = await c.req.json() as {
    name: string;
    subject: string;
    bodyHtml: string;
    bodyText?: string;
    category?: string;
    isShared?: boolean;
  };

  if (!body.name?.trim() || !body.subject?.trim() || !body.bodyHtml?.trim()) {
    return c.json({ error: 'Missing required fields: name, subject, bodyHtml' }, 400);
  }

  // Auto-detect merge fields from subject + body
  const allText = `${body.subject} ${body.bodyHtml}`;
  const mergeFields = extractMergeFields(allText);

  const id = generateId();
  const timestamp = now();

  await db.insert(emailTemplates).values({
    id,
    name: body.name.trim(),
    subject: body.subject.trim(),
    bodyHtml: body.bodyHtml,
    bodyText: body.bodyText ?? null,
    mergeFields: JSON.stringify(mergeFields),
    category: body.category?.trim() || null,
    isShared: body.isShared ?? false,
    ownerId: userId,
    createdAt: timestamp,
    updatedAt: timestamp,
  });

  return c.json({ id, mergeFields }, 201);
});

// ── PATCH /api/templates/:id — update template (owner only) ─────────────────

templateRoutes.patch('/api/templates/:id', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const db = c.get('db');
  const id = c.req.param('id');

  const existing = await db.query.emailTemplates.findFirst({
    where: eq(emailTemplates.id, id),
  });

  if (!existing) return c.json({ error: 'Template not found' }, 404);
  if (existing.ownerId !== userId) {
    return c.json({ error: 'Only the template owner can edit it' }, 403);
  }

  const body = await c.req.json() as {
    name?: string;
    subject?: string;
    bodyHtml?: string;
    bodyText?: string;
    category?: string;
    isShared?: boolean;
  };

  const updates: Record<string, unknown> = { updatedAt: now() };
  if (body.name !== undefined) updates.name = body.name.trim();
  if (body.subject !== undefined) updates.subject = body.subject.trim();
  if (body.bodyHtml !== undefined) updates.bodyHtml = body.bodyHtml;
  if (body.bodyText !== undefined) updates.bodyText = body.bodyText;
  if (body.category !== undefined) updates.category = body.category?.trim() || null;
  if (body.isShared !== undefined) updates.isShared = body.isShared;

  // Re-detect merge fields if subject or body changed
  const finalSubject = (updates.subject as string) ?? existing.subject;
  const finalBody = (updates.bodyHtml as string) ?? existing.bodyHtml;
  updates.mergeFields = JSON.stringify(extractMergeFields(`${finalSubject} ${finalBody}`));

  await db.update(emailTemplates).set(updates).where(eq(emailTemplates.id, id));

  return c.json({ updated: true });
});

// ── DELETE /api/templates/:id — delete template (owner only) ────────────────

templateRoutes.delete('/api/templates/:id', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const db = c.get('db');
  const id = c.req.param('id');

  const existing = await db.query.emailTemplates.findFirst({
    where: eq(emailTemplates.id, id),
  });

  if (!existing) return c.json({ error: 'Template not found' }, 404);
  if (existing.ownerId !== userId) {
    return c.json({ error: 'Only the template owner can delete it' }, 403);
  }

  await db.delete(emailTemplates).where(eq(emailTemplates.id, id));

  return c.json({ deleted: true });
});

// ── POST /api/templates/:id/preview — preview with sample merge data ────────

templateRoutes.post('/api/templates/:id/preview', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const db = c.get('db');
  const id = c.req.param('id');

  const template = await db.query.emailTemplates.findFirst({
    where: and(
      eq(emailTemplates.id, id),
      or(
        eq(emailTemplates.ownerId, userId),
        eq(emailTemplates.isShared, true),
      ),
    ),
  });

  if (!template) return c.json({ error: 'Template not found' }, 404);

  // Allow custom context, fall back to sample data
  let context: Record<string, unknown>;
  try {
    const body = await c.req.json();
    context = body.context ?? getSampleContext();
  } catch {
    context = getSampleContext();
  }

  return c.json({
    subject: resolveMergeFields(template.subject, context),
    bodyHtml: resolveMergeFields(template.bodyHtml, context),
  });
});

// ── POST /api/templates/:id/use — increment usage count ─────────────────────

templateRoutes.post('/api/templates/:id/use', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const db = c.get('db');
  const id = c.req.param('id');

  await db
    .update(emailTemplates)
    .set({ usageCount: sql`${emailTemplates.usageCount} + 1` })
    .where(eq(emailTemplates.id, id));

  return c.json({ incremented: true });
});
