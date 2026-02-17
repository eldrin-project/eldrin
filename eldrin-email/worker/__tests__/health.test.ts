import { describe, it, expect } from 'vitest';

describe('eldrin-email scaffold', () => {
  it('manifest has correct app id', async () => {
    const manifest = await import('../../public/eldrin-app.manifest.json');
    expect(manifest.id).toBe('eldrin-email');
    expect(manifest.name).toBe('Email');
  });

  it('manifest declares expected sideNav items', async () => {
    const manifest = await import('../../public/eldrin-app.manifest.json');
    const labels = manifest.ui.sideNav.map((item: { label: string }) => item.label);
    expect(labels).toContain('Inbox');
    expect(labels).toContain('Sent');
    expect(labels).toContain('Templates');
  });

  it('manifest declares email events', async () => {
    const manifest = await import('../../public/eldrin-app.manifest.json');
    const eventTypes = manifest.events.emits.map((e: { type: string }) => e.type);
    expect(eventTypes).toContain('email.received');
    expect(eventTypes).toContain('email.sent');
    expect(eventTypes).toContain('email.opened');
    expect(eventTypes).toContain('email.clicked');
  });

  it('manifest declares public tracking routes', async () => {
    const manifest = await import('../../public/eldrin-app.manifest.json');
    expect(manifest.api.publicRoutes).toContain('/api/track/:trackingId/pixel.gif');
    expect(manifest.api.publicRoutes).toContain('/api/track/:trackingId/click');
  });
});
