import { describe, it, expect } from 'vitest';
import { encryptToken, decryptToken } from '../services/crypto';

const TEST_SECRET = 'test-jwt-secret-at-least-32-chars-long';

describe('token encryption', () => {
  it('encrypts and decrypts a token round-trip', async () => {
    const original = 'ya29.some-access-token-from-google';
    const encrypted = await encryptToken(original, TEST_SECRET);

    // Encrypted value should not contain the original plaintext
    expect(encrypted).not.toContain(original);
    expect(encrypted.length).toBeGreaterThan(0);

    const decrypted = await decryptToken(encrypted, TEST_SECRET);
    expect(decrypted).toBe(original);
  });

  it('produces different ciphertext for the same plaintext (random IV)', async () => {
    const token = 'same-token-value';
    const a = await encryptToken(token, TEST_SECRET);
    const b = await encryptToken(token, TEST_SECRET);

    expect(a).not.toBe(b); // Different IVs
    expect(await decryptToken(a, TEST_SECRET)).toBe(token);
    expect(await decryptToken(b, TEST_SECRET)).toBe(token);
  });

  it('fails to decrypt with wrong secret', async () => {
    const encrypted = await encryptToken('secret-token', TEST_SECRET);
    await expect(decryptToken(encrypted, 'wrong-secret-key-different-length!!')).rejects.toThrow();
  });

  it('rejects malformed encrypted data', async () => {
    await expect(decryptToken('', TEST_SECRET)).rejects.toThrow('too short');
    await expect(decryptToken('abc', TEST_SECRET)).rejects.toThrow('too short');
  });

  it('handles long tokens (refresh tokens)', async () => {
    const longToken = '1//0' + 'a'.repeat(200) + '-refresh-token';
    const encrypted = await encryptToken(longToken, TEST_SECRET);
    const decrypted = await decryptToken(encrypted, TEST_SECRET);
    expect(decrypted).toBe(longToken);
  });

  it('handles tokens with special characters', async () => {
    const token = 'token/with+special=chars&more?yeah';
    const encrypted = await encryptToken(token, TEST_SECRET);
    const decrypted = await decryptToken(encrypted, TEST_SECRET);
    expect(decrypted).toBe(token);
  });
});
