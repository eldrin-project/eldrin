/**
 * Merge field extraction and resolution for email templates.
 *
 * Merge fields use {{dotted.path}} syntax (e.g. {{contact.firstName}}).
 * Extraction scans both subject and body HTML for placeholders.
 * Resolution replaces placeholders with values from a context object,
 * leaving unresolved fields as empty strings.
 */

const MERGE_FIELD_RE = /\{\{([a-zA-Z_][a-zA-Z0-9_.]*)\}\}/g;

/** Extract unique merge field names from text (subject or body HTML). */
export function extractMergeFields(text: string): string[] {
  const fields = new Set<string>();
  let match: RegExpExecArray | null;
  while ((match = MERGE_FIELD_RE.exec(text)) !== null) {
    fields.add(match[1]);
  }
  return Array.from(fields).sort();
}

/** Resolve a dotted path like "contact.firstName" against a nested object. */
function resolvePath(obj: Record<string, unknown>, path: string): string {
  const parts = path.split('.');
  let current: unknown = obj;
  for (const part of parts) {
    if (current == null || typeof current !== 'object') return '';
    current = (current as Record<string, unknown>)[part];
  }
  return current != null ? String(current) : '';
}

/** Replace all {{field}} placeholders in text with values from context. */
export function resolveMergeFields(
  text: string,
  context: Record<string, unknown>,
): string {
  return text.replace(MERGE_FIELD_RE, (_, field: string) => resolvePath(context, field));
}

/** Sample context for template preview. */
export function getSampleContext(): Record<string, unknown> {
  return {
    contact: {
      firstName: 'Jane',
      lastName: 'Smith',
      email: 'jane.smith@example.com',
      company: 'Acme Corp',
      phone: '+1 (555) 123-4567',
      title: 'VP of Engineering',
    },
    company: {
      name: 'Acme Corp',
      domain: 'acme.com',
      industry: 'Technology',
    },
    deal: {
      name: 'Enterprise License',
      value: '$25,000',
      stage: 'Proposal',
      closeDate: '2026-03-15',
    },
    user: {
      name: 'John Doe',
      email: 'john@company.com',
      title: 'Account Executive',
    },
  };
}
