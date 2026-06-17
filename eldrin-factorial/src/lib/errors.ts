export const NOT_CONFIGURED_HINT = 'Factorial is not configured. Set FACTORIAL_API_BASE_URL and FACTORIAL_API_KEY in app settings.';

export function isNotConfiguredError(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return message.toLowerCase().includes('not configured') || message.includes('400');
}
