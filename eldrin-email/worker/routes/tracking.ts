/**
 * Public tracking endpoints for email open and click tracking.
 *
 * These routes have NO authentication — they're loaded by recipients'
 * email clients (pixel) or browsers (click redirect).
 */

import { Hono } from 'hono';
import { eq, sql } from 'drizzle-orm';
import { emailTracking, trackingEvents, type Database } from '../db';
import { generateId, now } from '../utils';

type Variables = { db: Database; userId: string };

export const trackingRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

// 1x1 transparent GIF (43 bytes)
const TRANSPARENT_GIF = new Uint8Array([
  0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00,
  0x80, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21,
  0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00,
  0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
  0x01, 0x00, 0x3b,
]);

// ── GET /api/track/:trackingId/pixel.gif — open tracking ────────────────────

trackingRoutes.get('/api/track/:trackingId/pixel.gif', async (c) => {
  const { trackingId } = c.req.param();
  const db = c.get('db');

  // Record event non-blocking (after response is sent)
  c.executionCtx.waitUntil(recordOpenEvent(db, trackingId, c.req.raw));

  return new Response(TRANSPARENT_GIF, {
    status: 200,
    headers: {
      'Content-Type': 'image/gif',
      'Content-Length': String(TRANSPARENT_GIF.length),
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      Pragma: 'no-cache',
      Expires: '0',
    },
  });
});

// ── GET /api/track/:trackingId/click — click tracking + redirect ────────────

trackingRoutes.get('/api/track/:trackingId/click', async (c) => {
  const { trackingId } = c.req.param();
  const url = c.req.query('url');

  // Validate URL to prevent open redirect attacks
  if (!url || (!url.startsWith('https://') && !url.startsWith('http://'))) {
    return c.text('Invalid URL', 400);
  }

  const db = c.get('db');

  // Record event non-blocking
  c.executionCtx.waitUntil(recordClickEvent(db, trackingId, url, c.req.raw));

  return c.redirect(url, 302);
});

// ── Event recording helpers ─────────────────────────────────────────────────

async function recordOpenEvent(
  db: Database,
  trackingId: string,
  req: Request,
): Promise<void> {
  try {
    const timestamp = now();

    // Verify tracking record exists
    const tracking = await db.query.emailTracking.findFirst({
      where: eq(emailTracking.trackingId, trackingId),
      columns: { id: true, firstOpenedAt: true },
    });
    if (!tracking) return;

    // Insert event
    await db.insert(trackingEvents).values({
      id: generateId(),
      trackingId,
      eventType: 'open',
      userAgent: req.headers.get('User-Agent'),
      ipAddress: req.headers.get('CF-Connecting-IP'),
      createdAt: timestamp,
    });

    // Update counters
    const updates: Record<string, unknown> = {
      openCount: sql`${emailTracking.openCount} + 1`,
      lastOpenedAt: timestamp,
    };
    if (!tracking.firstOpenedAt) {
      updates.firstOpenedAt = timestamp;
    }

    await db.update(emailTracking)
      .set(updates)
      .where(eq(emailTracking.trackingId, trackingId));
  } catch {
    // Silently fail — tracking should never break the user experience
  }
}

async function recordClickEvent(
  db: Database,
  trackingId: string,
  url: string,
  req: Request,
): Promise<void> {
  try {
    const timestamp = now();

    // Verify tracking record exists
    const tracking = await db.query.emailTracking.findFirst({
      where: eq(emailTracking.trackingId, trackingId),
      columns: { id: true },
    });
    if (!tracking) return;

    // Insert event
    await db.insert(trackingEvents).values({
      id: generateId(),
      trackingId,
      eventType: 'click',
      url,
      userAgent: req.headers.get('User-Agent'),
      ipAddress: req.headers.get('CF-Connecting-IP'),
      createdAt: timestamp,
    });

    // Update click count
    await db.update(emailTracking)
      .set({ clickCount: sql`${emailTracking.clickCount} + 1` })
      .where(eq(emailTracking.trackingId, trackingId));
  } catch {
    // Silently fail
  }
}
