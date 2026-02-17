export function generateId(): string {
  return crypto.randomUUID();
}

export function now(): number {
  return Date.now();
}
