/**
 * Event emission helpers for the email app.
 *
 * Uses the platform SDK's EldrinEventClient to emit events to the core
 * event bus. Other apps (CRM, Workflows) can subscribe to these events
 * for cross-app integration.
 *
 * All emit calls are fire-and-forget — failures are logged but never
 * block the caller.
 */

import { createEventClient, type EldrinEventClient } from '@eldrin-project/eldrin-app-core';

let cachedClient: EldrinEventClient | null = null;

function getClient(env: Env): EldrinEventClient {
  if (!cachedClient) {
    cachedClient = createEventClient(env as unknown as Record<string, unknown>, 'eldrin-email');
  }
  return cachedClient;
}

// ── Payload types ────────────────────────────────────────────────────────────

/**
 * Cap for `bodyText` on the email.received payload. Roughly one page of
 * plain text — enough for downstream signature parsing (CRM auto-capture)
 * without bloating the event bus with full email bodies.
 */
export const BODY_TEXT_MAX = 4000;

export interface EmailReceivedPayload {
  messageId: string;
  threadId: string;
  /** Receiving mailbox — lets consumers attribute the relationship (CRM assigned-mailbox). */
  mailboxId: string;
  mailboxEmail: string;
  from: string;
  to: string[];
  subject: string | null;
  snippet: string | null;
  /**
   * Plain-text body truncated to BODY_TEXT_MAX characters. Null when the
   * mailbox sync depth does not fetch bodies (metadata / thread_only).
   */
  bodyText: string | null;
  receivedAt: number;
}

export interface EmailSentPayload {
  messageId: string;
  from: string;
  to: string[];
  subject: string;
  templateId?: string;
  relatedApp?: string;
  relatedRecordId?: string;
}

// ── Payload helpers ──────────────────────────────────────────────────────────

/**
 * Build the truncated `bodyText` for an email.received payload.
 *
 * Prefers the parsed plain-text body; falls back to tag-stripped HTML (the
 * same stripping approach used when building `snippet` elsewhere in this
 * worker); returns null when neither is available — with metadata or
 * thread_only sync depth the provider parse carries no body at all.
 *
 * Defensive by design: never throws, so body extraction can never break
 * the sync loop.
 */
export function buildEventBodyText(
  bodyText: string | null | undefined,
  bodyHtml: string | null | undefined,
): string | null {
  try {
    const source = bodyText ?? (bodyHtml ? bodyHtml.replace(/<[^>]*>/g, ' ') : null);
    if (!source) return null;
    const trimmed = source.trim();
    return trimmed.length > 0 ? trimmed.slice(0, BODY_TEXT_MAX) : null;
  } catch {
    return null;
  }
}

// ── Emitters ─────────────────────────────────────────────────────────────────

export function emitEmailReceived(env: Env, payload: EmailReceivedPayload): Promise<void> {
  return getClient(env)
    .emit('email.received', payload)
    .then(() => {})
    .catch((err) => console.error('[email] Failed to emit email.received:', err));
}

export function emitEmailSent(env: Env, payload: EmailSentPayload): Promise<void> {
  return getClient(env)
    .emit('email.sent', payload)
    .then(() => {})
    .catch((err) => console.error('[email] Failed to emit email.sent:', err));
}
