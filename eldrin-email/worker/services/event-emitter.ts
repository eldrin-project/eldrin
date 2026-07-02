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

export interface EmailReceivedPayload {
  messageId: string;
  threadId: string;
  from: string;
  to: string[];
  subject: string | null;
  snippet: string | null;
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
