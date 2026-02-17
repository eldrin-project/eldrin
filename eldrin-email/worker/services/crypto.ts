/**
 * Token encryption/decryption using AES-GCM with HKDF key derivation.
 *
 * Same pattern as TOTP secret encryption in eldrin-core/core/auth/totp.ts,
 * but with a different salt ('eldrin-email-oauth') to produce a distinct key.
 *
 * Format: base64url(IV[12] + ciphertext)
 */

const SALT = 'eldrin-email-oauth';
const INFO = 'aes-gcm-key';
const IV_LENGTH = 12;

// ── Base64url helpers (no padding, URL-safe) ─────────────────────────────────

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ── Key derivation ───────────────────────────────────────────────────────────

async function deriveKey(secret: string): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    'HKDF',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode(SALT),
      info: new TextEncoder().encode(INFO),
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Encrypt a token string for database storage.
 * Returns base64url(IV + ciphertext).
 */
export async function encryptToken(token: string, secret: string): Promise<string> {
  const key = await deriveKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const plaintext = new TextEncoder().encode(token);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintext,
  );

  const combined = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), IV_LENGTH);

  return base64UrlEncode(combined);
}

/**
 * Decrypt a token string from database storage.
 */
export async function decryptToken(encrypted: string, secret: string): Promise<string> {
  const key = await deriveKey(secret);
  const combined = base64UrlDecode(encrypted);

  if (combined.length < IV_LENGTH + 1) {
    throw new Error('Invalid encrypted token: too short');
  }

  const iv = combined.slice(0, IV_LENGTH);
  const ciphertext = combined.slice(IV_LENGTH);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext,
  );

  return new TextDecoder().decode(decrypted);
}
