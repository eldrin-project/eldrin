import { describe, it, expect } from 'vitest';
import { BODY_TEXT_MAX, buildEventBodyText } from '../services/event-emitter';

describe('buildEventBodyText', () => {
  it('prefers the plain-text body when both are available', () => {
    expect(buildEventBodyText('plain body', '<p>html body</p>')).toBe('plain body');
  });

  it('falls back to tag-stripped HTML when no plain text exists', () => {
    const result = buildEventBodyText(null, '<div>Hello <b>world</b></div>');
    expect(result).toBe('Hello  world');
  });

  it('returns null when neither body form is available (metadata sync depth)', () => {
    expect(buildEventBodyText(null, null)).toBeNull();
    expect(buildEventBodyText(undefined, undefined)).toBeNull();
  });

  it('returns null for whitespace-only bodies', () => {
    expect(buildEventBodyText('   \n  ', null)).toBeNull();
    expect(buildEventBodyText(null, '<p>  </p>')).toBeNull();
  });

  it('truncates to BODY_TEXT_MAX characters', () => {
    const long = 'a'.repeat(BODY_TEXT_MAX + 500);
    const result = buildEventBodyText(long, null);
    expect(result).toHaveLength(BODY_TEXT_MAX);
    expect(long.startsWith(result!)).toBe(true);
  });

  it('trims surrounding whitespace before truncating', () => {
    expect(buildEventBodyText('  hello  ', null)).toBe('hello');
  });
});
