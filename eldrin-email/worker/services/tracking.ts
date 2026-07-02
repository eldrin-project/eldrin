/**
 * Email tracking injection service.
 *
 * Injects a transparent tracking pixel and wraps links for click tracking
 * before sending outbound emails.
 */

import { emailTracking, type Database } from '../db';
import { generateId, now } from '../utils';

/**
 * Inject a 1x1 transparent tracking pixel before </body> (or at end of HTML).
 */
export function injectTrackingPixel(
  html: string,
  trackingId: string,
  baseUrl: string,
): string {
  const pixelUrl = `${baseUrl}/api/track/${trackingId}/pixel.gif`;
  const pixelTag = `<img src="${pixelUrl}" width="1" height="1" alt="" style="display:block;width:1px;height:1px;border:0;" />`;

  // Insert before </body> if present, otherwise append
  const bodyCloseIdx = html.lastIndexOf('</body>');
  if (bodyCloseIdx !== -1) {
    return html.slice(0, bodyCloseIdx) + pixelTag + html.slice(bodyCloseIdx);
  }
  return html + pixelTag;
}

/**
 * Wrap all <a href="..."> links with click tracking redirects.
 * Skips mailto:, tel:, and # links.
 */
export function wrapLinksWithTracking(
  html: string,
  trackingId: string,
  baseUrl: string,
): string {
  // Match <a ... href="..." ...> — capture the href value
  return html.replace(
    /(<a\s[^>]*href\s*=\s*["'])([^"']+)(["'][^>]*>)/gi,
    (_match, before: string, url: string, after: string) => {
      // Skip non-trackable URLs
      if (
        url.startsWith('mailto:') ||
        url.startsWith('tel:') ||
        url.startsWith('#') ||
        url.startsWith('javascript:')
      ) {
        return before + url + after;
      }

      const trackedUrl = `${baseUrl}/api/track/${trackingId}/click?url=${encodeURIComponent(url)}`;
      return before + trackedUrl + after;
    },
  );
}

/**
 * Create a tracking record and inject pixel + link tracking into HTML.
 * Returns the modified HTML with tracking injected.
 */
export async function prepareTrackedEmail(
  db: Database,
  html: string,
  emailId: string,
  baseUrl: string,
): Promise<{ html: string; trackingId: string }> {
  const trackingId = generateId();
  const timestamp = now();

  // Create tracking record
  await db.insert(emailTracking).values({
    id: generateId(),
    emailId,
    trackingId,
    openCount: 0,
    clickCount: 0,
    createdAt: timestamp,
  });

  // Inject pixel and wrap links
  let tracked = injectTrackingPixel(html, trackingId, baseUrl);
  tracked = wrapLinksWithTracking(tracked, trackingId, baseUrl);

  return { html: tracked, trackingId };
}
