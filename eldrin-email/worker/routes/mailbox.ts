import { Hono } from 'hono';
import { eq, and } from 'drizzle-orm';
import { connectedMailboxes, type Database } from '../db';
import { generateId, now } from '../utils';
import { encryptToken, decryptToken } from '../services/crypto';
import {
  getGmailAuthUrl,
  exchangeGmailCode,
  getGoogleUserInfo,
  revokeGmailToken,
} from '../services/oauth-gmail';

type Variables = { db: Database };

export const mailboxRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

// ── GET /api/mailbox/connect/gmail — redirect to Google OAuth ────────────────

mailboxRoutes.get('/api/mailbox/connect/gmail', async (c) => {
  const userId = c.req.header('X-Eldrin-User-Id');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const redirectUri = new URL('/api/mailbox/callback/gmail', c.req.url).toString();

  // State encodes user ID for the callback (CSRF protection via platform proxy)
  const state = btoa(JSON.stringify({ userId, ts: now() }));

  const authUrl = getGmailAuthUrl(c.env.GOOGLE_CLIENT_ID, redirectUri, state);
  return c.redirect(authUrl);
});

// ── GET /api/mailbox/callback/gmail — handle OAuth callback ──────────────────

mailboxRoutes.get('/api/mailbox/callback/gmail', async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state');
  const error = c.req.query('error');

  if (error) {
    // User denied access or other OAuth error
    return c.html(`<script>window.close();</script><p>Authorization cancelled: ${error}</p>`);
  }

  if (!code || !state) {
    return c.json({ error: 'Missing code or state parameter' }, 400);
  }

  let userId: string;
  try {
    const parsed = JSON.parse(atob(state)) as { userId: string; ts: number };
    userId = parsed.userId;

    // Reject states older than 10 minutes
    if (now() - parsed.ts > 10 * 60 * 1000) {
      return c.json({ error: 'OAuth state expired' }, 400);
    }
  } catch {
    return c.json({ error: 'Invalid state parameter' }, 400);
  }

  const redirectUri = new URL('/api/mailbox/callback/gmail', c.req.url);
  redirectUri.search = '';
  const redirectUriStr = redirectUri.toString();

  try {
    // Exchange code for tokens
    const tokens = await exchangeGmailCode(
      code,
      c.env.GOOGLE_CLIENT_ID,
      c.env.GOOGLE_CLIENT_SECRET,
      redirectUriStr,
    );

    // Get user info (email, display name)
    const userInfo = await getGoogleUserInfo(tokens.accessToken);

    // Encrypt tokens for storage
    const [accessTokenEncrypted, refreshTokenEncrypted] = await Promise.all([
      encryptToken(tokens.accessToken, c.env.JWT_SECRET),
      encryptToken(tokens.refreshToken, c.env.JWT_SECRET),
    ]);

    const db = c.get('db');
    const timestamp = now();
    const id = generateId();

    // Upsert: if same provider+email already exists, update tokens
    const existing = await db.query.connectedMailboxes.findFirst({
      where: and(
        eq(connectedMailboxes.provider, 'gmail'),
        eq(connectedMailboxes.emailAddress, userInfo.email),
      ),
    });

    if (existing) {
      await db.update(connectedMailboxes)
        .set({
          accessTokenEncrypted,
          refreshTokenEncrypted,
          tokenExpiresAt: timestamp + tokens.expiresIn * 1000,
          displayName: userInfo.name,
          syncStatus: 'active',
          errorMessage: null,
          updatedAt: timestamp,
        })
        .where(eq(connectedMailboxes.id, existing.id));
    } else {
      await db.insert(connectedMailboxes).values({
        id,
        userId,
        provider: 'gmail',
        emailAddress: userInfo.email,
        displayName: userInfo.name,
        accessTokenEncrypted,
        refreshTokenEncrypted,
        tokenExpiresAt: timestamp + tokens.expiresIn * 1000,
        syncStatus: 'active',
        syncDepth: 'metadata',
        createdAt: timestamp,
        updatedAt: timestamp,
      });
    }

    // Close the OAuth popup and notify the parent window
    return c.html(`
      <script>
        if (window.opener) {
          window.opener.postMessage({ type: 'eldrin-email:mailbox-connected' }, '*');
        }
        window.close();
      </script>
      <p>Gmail connected successfully. You can close this window.</p>
    `);
  } catch (err) {
    console.error('[email] Gmail OAuth callback error:', err);
    return c.html(`
      <script>
        if (window.opener) {
          window.opener.postMessage({ type: 'eldrin-email:mailbox-error', error: 'Connection failed' }, '*');
        }
        window.close();
      </script>
      <p>Failed to connect Gmail. Please try again.</p>
    `);
  }
});

// ── GET /api/mailboxes — list user's connected mailboxes ─────────────────────

mailboxRoutes.get('/api/mailboxes', async (c) => {
  const userId = c.req.header('X-Eldrin-User-Id');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const db = c.get('db');
  const mailboxes = await db.query.connectedMailboxes.findMany({
    where: eq(connectedMailboxes.userId, userId),
    columns: {
      id: true,
      provider: true,
      emailAddress: true,
      displayName: true,
      lastSyncAt: true,
      syncStatus: true,
      syncDepth: true,
      errorMessage: true,
      createdAt: true,
      updatedAt: true,
      // Omit encrypted tokens from list response
    },
  });

  return c.json({ mailboxes });
});

// ── DELETE /api/mailboxes/:id — disconnect mailbox ───────────────────────────

mailboxRoutes.delete('/api/mailboxes/:id', async (c) => {
  const userId = c.req.header('X-Eldrin-User-Id');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const id = c.req.param('id');
  const db = c.get('db');

  const mailbox = await db.query.connectedMailboxes.findFirst({
    where: and(
      eq(connectedMailboxes.id, id),
      eq(connectedMailboxes.userId, userId),
    ),
  });

  if (!mailbox) return c.json({ error: 'Mailbox not found' }, 404);

  // Best-effort token revocation
  try {
    const refreshToken = await decryptToken(mailbox.refreshTokenEncrypted, c.env.JWT_SECRET);
    await revokeGmailToken(refreshToken);
  } catch (err) {
    console.warn('[email] Token revocation failed (continuing with deletion):', err);
  }

  await db.delete(connectedMailboxes).where(eq(connectedMailboxes.id, id));

  return c.json({ deleted: true });
});

// ── PATCH /api/mailboxes/:id — update mailbox settings ───────────────────────

mailboxRoutes.patch('/api/mailboxes/:id', async (c) => {
  const userId = c.req.header('X-Eldrin-User-Id');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const id = c.req.param('id');
  const body = await c.req.json() as { syncDepth?: string };

  const validDepths = ['full', 'metadata', 'thread_only'];
  if (body.syncDepth && !validDepths.includes(body.syncDepth)) {
    return c.json({ error: `Invalid sync depth. Must be one of: ${validDepths.join(', ')}` }, 400);
  }

  const db = c.get('db');

  const mailbox = await db.query.connectedMailboxes.findFirst({
    where: and(
      eq(connectedMailboxes.id, id),
      eq(connectedMailboxes.userId, userId),
    ),
  });

  if (!mailbox) return c.json({ error: 'Mailbox not found' }, 404);

  const updates: Record<string, unknown> = { updatedAt: now() };
  if (body.syncDepth) updates.syncDepth = body.syncDepth;

  await db.update(connectedMailboxes)
    .set(updates)
    .where(eq(connectedMailboxes.id, id));

  return c.json({ updated: true });
});

// ── POST /api/mailboxes/:id/pause — pause sync ──────────────────────────────

mailboxRoutes.post('/api/mailboxes/:id/pause', async (c) => {
  const userId = c.req.header('X-Eldrin-User-Id');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const id = c.req.param('id');
  const db = c.get('db');

  const mailbox = await db.query.connectedMailboxes.findFirst({
    where: and(
      eq(connectedMailboxes.id, id),
      eq(connectedMailboxes.userId, userId),
    ),
  });

  if (!mailbox) return c.json({ error: 'Mailbox not found' }, 404);

  await db.update(connectedMailboxes)
    .set({ syncStatus: 'paused', updatedAt: now() })
    .where(eq(connectedMailboxes.id, id));

  return c.json({ updated: true });
});

// ── POST /api/mailboxes/:id/resume — resume sync ────────────────────────────

mailboxRoutes.post('/api/mailboxes/:id/resume', async (c) => {
  const userId = c.req.header('X-Eldrin-User-Id');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const id = c.req.param('id');
  const db = c.get('db');

  const mailbox = await db.query.connectedMailboxes.findFirst({
    where: and(
      eq(connectedMailboxes.id, id),
      eq(connectedMailboxes.userId, userId),
    ),
  });

  if (!mailbox) return c.json({ error: 'Mailbox not found' }, 404);

  await db.update(connectedMailboxes)
    .set({ syncStatus: 'active', errorMessage: null, updatedAt: now() })
    .where(eq(connectedMailboxes.id, id));

  return c.json({ updated: true });
});
