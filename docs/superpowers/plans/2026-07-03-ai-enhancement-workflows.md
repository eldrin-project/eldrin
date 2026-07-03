# AI Enhancement via eldrin-workflows — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** CRM records auto-enrich themselves — companies from their website metadata, contacts from LLM email extraction — via two importable eldrin-workflows definitions, with a `pending`/`enhanced` flag as the durable source of truth.

**Architecture:** Three generic workflow steps (`call_app_api`, `html_extract`, `ai_extract` with a mock/openai/claude provider registry) + a core-proxy service-principal branch let JSON workflow definitions react to CRM events (`company.created`, `email.extraction.requested`) and write results back through service-secret-gated CRM apply endpoints. The CRM arms an `ai_enhancement_status` flag at capture time; any failure leaves it `pending` for retry/pull.

**Tech Stack:** Cloudflare Workers, Hono 4, drizzle-orm (D1), vitest + better-sqlite3, React 19, `@anthropic-ai/sdk` (claude provider), spec: `docs/superpowers/specs/2026-07-03-ai-enhancement-workflows-design.md`.

## Global Constraints

- Three repos, three branches: `eldrin-workflows` → new branch `feature/ai-enhancement`; `eldrin-core` → new branch `feature/service-principal-proxy`; `eldrin-crm` → continue existing branch `feature/phase-07-email-integration`. Parent repo (`eldrin-backup`) only for docs + pointer bumps at the end.
- Conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`); attribution disabled globally — never add Co-Authored-By.
- TypeScript strict; immutable patterns (spread, never mutate); files < 400 lines; validate all external input at boundaries; no hardcoded secrets — env/`.dev.vars` only (`.dev.vars` is gitignored; update `.dev.vars.example` with placeholders).
- Test commands: `cd eldrin-workflows && npx vitest run` (new in this plan), `cd eldrin-crm && npx vitest run`, `cd eldrin-core && npx vitest run core/app.test.ts`.
- CRM migration filenames MUST be 14-digit timestamps (`YYYYMMDDHHMMSS-description.sql`) or they are silently skipped; after adding a migration run `npm run generate:migrations` (regenerates `worker/migrations.generated.ts`).
- Bash cwd persists between commands — always use `git -C <repo>` or check `pwd` before git commands (multi-repo gotcha).
- The shared dev `JWT_SECRET` lives in each app's local `.dev.vars` and must match eldrin-core's. Never commit it.

## Deviations from the spec (agreed refinements)

1. **Apply/pull endpoints live under `/api/enhancement/*`** (`POST /api/enhancement/companies/:id`, `POST /api/enhancement/contacts/:id`, `GET /api/enhancement/pending`) instead of `/api/companies/:id/apply-enrichment`. Reason: the manifest permission middleware only supports prefix wildcards in `publicRoutes` (like `/rooms/*`); one `/enhancement/*` entry + in-handler service-secret check follows the proven `_events/webhook` pattern. The admin-JWT alternative is dropped — no caller needs it (the Enhance-now button triggers a workflow run, never an apply).
2. **Import route is bulk + idempotent by name**: `POST /api/workflows/import` takes `{workflows: [...]}` and skips names that already exist — re-running the seed never duplicates. (Single-create already exists as `POST /api/workflows`.)
3. **Schema validation of LLM output** in eldrin-workflows is a small local JSON-schema validator (`validate-schema.ts`), not a zod dependency. The CRM re-validates at its own boundary (defense in depth).
4. **`insights.companyName` / `insights.address` are accepted but not applied** this slice (the apply endpoint applies jobTitle/phones/social via the existing `applySignatureToContact`).
5. **`description` from enrichment maps to `companies.notes`** — the companies table has no description column.

---

### Task 1: eldrin-workflows test infrastructure

The repo has NO test tooling (no vitest, no test script, no test files — verified). Bootstrap it with a characterization test of existing interpolation behavior.

**Files:**
- Modify: `eldrin-workflows/package.json` (devDeps + script)
- Create: `eldrin-workflows/vitest.config.ts`
- Test: `eldrin-workflows/worker/engine/interpolation.test.ts`

**Interfaces:**
- Produces: `npx vitest run` green in eldrin-workflows; later tasks add tests under `worker/**/*.test.ts`.

- [ ] **Step 1: Create the branch and install dev deps**

```bash
git -C eldrin-workflows checkout -b feature/ai-enhancement
cd eldrin-workflows && npm install -D vitest better-sqlite3 @types/better-sqlite3 && cd ..
```

(better-sqlite3 is used by Task 7's DB-backed route test; install once here.)

- [ ] **Step 2: Add vitest config and test script**

Create `eldrin-workflows/vitest.config.ts`:

```ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['worker/**/*.test.ts'],
  },
});
```

In `eldrin-workflows/package.json` scripts, add:

```json
"test": "vitest run",
```

- [ ] **Step 3: Write the characterization test**

Create `eldrin-workflows/worker/engine/interpolation.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { interpolateString, interpolateConfig } from './interpolation';
import type { ExecutionContext } from './types';

function ctx(overrides: Partial<ExecutionContext> = {}): ExecutionContext {
  return {
    workflowId: 'wf1',
    runId: 'run1',
    trigger: { type: 'event', data: {} },
    payload: {},
    steps: {},
    env: {},
    ...overrides,
  };
}

describe('interpolateString', () => {
  it('substitutes payload paths inside a string', () => {
    const c = ctx({ payload: { domain: 'acme.com' } });
    expect(interpolateString('https://{{payload.domain}}/x', c)).toBe('https://acme.com/x');
  });

  it('renders undefined paths as empty string', () => {
    expect(interpolateString('v={{payload.missing}}', ctx())).toBe('v=');
  });
});

describe('interpolateConfig', () => {
  it('interpolates nested string values', () => {
    const c = ctx({ payload: { id: '42' } });
    expect(interpolateConfig({ a: { b: 'id-{{payload.id}}' } }, c)).toEqual({
      a: { b: 'id-42' },
    });
  });
});
```

- [ ] **Step 4: Run tests — expect PASS (characterization of existing code)**

Run: `cd eldrin-workflows && npx vitest run`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git -C eldrin-workflows add package.json package-lock.json vitest.config.ts worker/engine/interpolation.test.ts
git -C eldrin-workflows commit -m "test: bootstrap vitest with interpolation characterization tests"
```

---

### Task 2: whole-value interpolation

Today `interpolateConfig` JSON-stringifies objects when a config value is exactly one `{{expr}}` (verified in `interpolation.ts:48,60-67`). The shipped workflows need `"body": {"data": "{{steps.extract.output}}"}` to substitute the *object*.

**Files:**
- Modify: `eldrin-workflows/worker/engine/interpolation.ts`
- Test: `eldrin-workflows/worker/engine/interpolation.test.ts`

**Interfaces:**
- Produces: `resolveExpression(path: string, context: ExecutionContext): unknown` (exported); new `interpolateConfig` semantics: a string value that is EXACTLY `{{expr}}` becomes the resolved raw value (object/array/number/boolean/string; `''` when undefined/null). Mixed strings keep old stringify behavior.

- [ ] **Step 1: Write failing tests** (append to `interpolation.test.ts`)

```ts
describe('interpolateConfig whole-value substitution', () => {
  it('substitutes an object when the value is exactly one expression', () => {
    const c = ctx({ steps: { extract: { output: { name: 'Acme', logoUrl: 'x' } } } });
    const out = interpolateConfig({ body: { data: '{{steps.extract.output}}' } }, c);
    expect(out).toEqual({ body: { data: { name: 'Acme', logoUrl: 'x' } } });
  });

  it('substitutes numbers and booleans as raw values', () => {
    const c = ctx({ payload: { n: 5, flag: true } });
    expect(interpolateConfig({ a: '{{payload.n}}', b: '{{payload.flag}}' }, c)).toEqual({
      a: 5,
      b: true,
    });
  });

  it('keeps stringify behavior for mixed strings', () => {
    const c = ctx({ payload: { user: { id: 1 } } });
    expect(interpolateConfig({ a: 'u={{payload.user}}' }, c)).toEqual({ a: 'u={"id":1}' });
  });

  it('resolves whole-value undefined to empty string', () => {
    expect(interpolateConfig({ a: '{{payload.nope}}' }, ctx())).toEqual({ a: '' });
  });
});
```

- [ ] **Step 2: Run to verify the new tests fail**

Run: `cd eldrin-workflows && npx vitest run`
Expected: FAIL — object case comes back as a JSON string, number case as `"5"`.

- [ ] **Step 3: Implement**

In `eldrin-workflows/worker/engine/interpolation.ts`, extract the path-resolution branch out of `interpolateString` and add whole-value handling to `interpolateConfig`:

```ts
const WHOLE_EXPRESSION = /^\{\{([^}]+)\}\}$/;

/** Resolve one {{…}} expression body to its raw context value. */
export function resolveExpression(path: string, context: ExecutionContext): unknown {
  const trimmed = path.trim();
  if (trimmed.startsWith('payload.')) {
    return resolveValue(context.payload, trimmed.slice('payload.'.length));
  }
  if (trimmed.startsWith('trigger.')) {
    return resolveValue(context.trigger, trimmed.slice('trigger.'.length));
  }
  if (trimmed.startsWith('steps.')) {
    return resolveValue(context.steps, trimmed.slice('steps.'.length));
  }
  if (trimmed.startsWith('env.')) {
    return resolveValue(context.env, trimmed.slice('env.'.length));
  }
  return resolveValue(context, trimmed);
}

export function interpolateString(
  template: string,
  context: ExecutionContext,
): string {
  return template.replace(/\{\{([^}]+)\}\}/g, (_match, path: string) => {
    const value = resolveExpression(path, context);
    if (value === undefined || value === null) return '';
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
  });
}

export function interpolateConfig(
  config: Record<string, unknown>,
  context: ExecutionContext,
): Record<string, unknown> {
  return JSON.parse(
    JSON.stringify(config, (_key, value) => {
      if (typeof value === 'string') {
        const whole = value.match(WHOLE_EXPRESSION);
        if (whole) {
          const resolved = resolveExpression(whole[1], context);
          // Preserve the legacy contract: unresolvable → empty string.
          if (resolved === undefined || resolved === null) return '';
          return resolved;
        }
        return interpolateString(value, context);
      }
      return value;
    }),
  );
}
```

Keep the existing `resolveValue` function unchanged above these.

- [ ] **Step 4: Run all tests**

Run: `cd eldrin-workflows && npx vitest run`
Expected: all pass (including the Task 1 characterization tests — mixed-string behavior is unchanged).

- [ ] **Step 5: Commit**

```bash
git -C eldrin-workflows add worker/engine/interpolation.ts worker/engine/interpolation.test.ts
git -C eldrin-workflows commit -m "feat(engine): whole-value {{expr}} substitution in step configs"
```

---

### Task 3: `html_extract` step

Pure metadata parser: title/meta/OG out of fetched HTML. No network, no dependency.

**Files:**
- Create: `eldrin-workflows/worker/engine/steps/html-extract.ts`
- Modify: `eldrin-workflows/worker/engine/registry.ts` (register), `eldrin-workflows/worker/validation.ts` (STEP_TYPES)
- Test: `eldrin-workflows/worker/engine/steps/html-extract.test.ts`

**Interfaces:**
- Consumes: `StepRunner`/`StepResult` from `../types`.
- Produces: step type `html_extract`; config `{html: string, baseUrl?: string}`; output `{name?: string, description?: string, logoUrl?: string}` (keys omitted when not found). Empty findings are still `success: true` with `{}`.

- [ ] **Step 1: Write failing tests**

Create `eldrin-workflows/worker/engine/steps/html-extract.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { htmlExtractRunner } from './html-extract';
import type { ExecutionContext } from '../types';

const ctx = {} as ExecutionContext; // step never reads context

const PAGE = `<!doctype html><html><head>
<title>Acme Corp — Home</title>
<meta name="description" content="We make &amp; sell anvils">
<meta property="og:site_name" content="Acme Corp">
<meta content="https://cdn.acme.com/logo.png" property="og:image">
</head><body>hi</body></html>`;

describe('html_extract', () => {
  it('extracts name, description and logoUrl', async () => {
    const r = await htmlExtractRunner.execute({ html: PAGE }, ctx);
    expect(r.success).toBe(true);
    expect(r.output).toEqual({
      name: 'Acme Corp',
      description: 'We make & sell anvils',
      logoUrl: 'https://cdn.acme.com/logo.png',
    });
  });

  it('falls back og:title then <title> for name', async () => {
    const r = await htmlExtractRunner.execute(
      { html: '<title>Fallback Co</title>' },
      ctx,
    );
    expect((r.output as Record<string, unknown>).name).toBe('Fallback Co');
  });

  it('resolves a relative og:image against baseUrl', async () => {
    const html = '<meta property="og:image" content="/logo.svg">';
    const r = await htmlExtractRunner.execute({ html, baseUrl: 'https://acme.com' }, ctx);
    expect((r.output as Record<string, unknown>).logoUrl).toBe('https://acme.com/logo.svg');
  });

  it('returns success with empty output when nothing is found', async () => {
    const r = await htmlExtractRunner.execute({ html: '<p>nothing here</p>' }, ctx);
    expect(r.success).toBe(true);
    expect(r.output).toEqual({});
  });

  it('fails when html is missing', async () => {
    const r = await htmlExtractRunner.execute({}, ctx);
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/html/i);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd eldrin-workflows && npx vitest run worker/engine/steps/html-extract.test.ts`
Expected: FAIL — cannot find module `./html-extract`.

- [ ] **Step 3: Implement**

Create `eldrin-workflows/worker/engine/steps/html-extract.ts`:

```ts
import type { StepRunner, StepResult } from '../types';

/** Cap parsing input; homepages larger than this are truncated first. */
const MAX_HTML_CHARS = 262144; // 256 KB

const ENTITIES: Record<string, string> = {
  '&amp;': '&',
  '&lt;': '<',
  '&gt;': '>',
  '&quot;': '"',
  '&#39;': "'",
  '&apos;': "'",
};

function decodeEntities(text: string): string {
  return text.replace(/&(?:amp|lt|gt|quot|#39|apos);/g, (m) => ENTITIES[m] ?? m);
}

/** Read <meta name|property="key" content="…"> regardless of attribute order. */
function metaContent(html: string, attr: 'name' | 'property', key: string): string | undefined {
  const tagRe = new RegExp(`<meta\\b[^>]*\\b${attr}\\s*=\\s*["']${key}["'][^>]*>`, 'i');
  const tag = html.match(tagRe)?.[0];
  if (!tag) return undefined;
  const content = tag.match(/\bcontent\s*=\s*["']([^"']*)["']/i)?.[1];
  const trimmed = content?.trim();
  return trimmed ? decodeEntities(trimmed) : undefined;
}

function titleText(html: string): string | undefined {
  const raw = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1];
  const trimmed = raw?.replace(/\s+/g, ' ').trim();
  if (!trimmed) return undefined;
  // Drop common " — tagline" / " | tagline" suffixes.
  return decodeEntities(trimmed.split(/\s+[|—–-]\s+/)[0].trim());
}

function resolveLogoUrl(raw: string | undefined, baseUrl: string | undefined): string | undefined {
  if (!raw) return undefined;
  try {
    return baseUrl ? new URL(raw, baseUrl).toString() : new URL(raw).toString();
  } catch {
    return undefined; // relative URL without a baseUrl, or garbage
  }
}

export const htmlExtractRunner: StepRunner = {
  type: 'html_extract',
  async execute(config): Promise<StepResult> {
    const rawHtml = config.html;
    if (typeof rawHtml !== 'string' || rawHtml.length === 0) {
      return { success: false, error: 'html is required' };
    }
    const html = rawHtml.slice(0, MAX_HTML_CHARS);
    const baseUrl = typeof config.baseUrl === 'string' ? config.baseUrl : undefined;

    const name =
      metaContent(html, 'property', 'og:site_name') ??
      metaContent(html, 'property', 'og:title') ??
      titleText(html);
    const description =
      metaContent(html, 'name', 'description') ??
      metaContent(html, 'property', 'og:description');
    const logoUrl = resolveLogoUrl(metaContent(html, 'property', 'og:image'), baseUrl);

    return {
      success: true,
      output: {
        ...(name ? { name } : {}),
        ...(description ? { description } : {}),
        ...(logoUrl ? { logoUrl } : {}),
      },
    };
  },
};
```

Register it — in `eldrin-workflows/worker/engine/registry.ts` add:

```ts
import { htmlExtractRunner } from './steps/html-extract';
// … with the other registerStep calls:
registerStep(htmlExtractRunner);
```

Allowlist it — in `eldrin-workflows/worker/validation.ts` add `'html_extract',` to the `STEP_TYPES` array (after `'call_app_api',`).

- [ ] **Step 4: Run tests**

Run: `cd eldrin-workflows && npx vitest run`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git -C eldrin-workflows add worker/engine/steps/html-extract.ts worker/engine/steps/html-extract.test.ts worker/engine/registry.ts worker/validation.ts
git -C eldrin-workflows commit -m "feat(engine): html_extract step — title/meta/OG metadata parser"
```

---

### Task 4: JSON-schema validator, AI provider registry, mock provider, `ai_extract` step

**Files:**
- Create: `eldrin-workflows/worker/engine/ai/validate-schema.ts`, `eldrin-workflows/worker/engine/ai/types.ts`, `eldrin-workflows/worker/engine/ai/registry.ts`, `eldrin-workflows/worker/engine/ai/providers/mock.ts`, `eldrin-workflows/worker/engine/steps/ai-extract.ts`
- Modify: `eldrin-workflows/worker/engine/registry.ts`, `eldrin-workflows/worker/validation.ts`
- Test: `eldrin-workflows/worker/engine/ai/validate-schema.test.ts`, `eldrin-workflows/worker/engine/steps/ai-extract.test.ts`

**Interfaces:**
- Produces:
  - `validateAgainstSchema(value: unknown, schema: Record<string, unknown>, path?: string): string[]` — empty array = valid. Supports `type` (object/array/string/number/boolean), `properties`, `required`, `items`, `additionalProperties: false`.
  - `interface ExtractRequest { prompt: string; input: string; schema: Record<string, unknown>; env: Record<string, unknown>; }`
  - `interface AiProvider { name: string; extract(req: ExtractRequest): Promise<unknown>; }`
  - `getAiProvider(name: string): AiProvider | undefined` (registry; `mock` registered here, `openai`/`claude` in Task 5)
  - step type `ai_extract`; config `{provider?, prompt, input, schema}`; output = the schema-validated extraction object. Provider resolution: `config.provider` → `env.AI_PROVIDER` → `'mock'`. 30 s timeout. Invalid output → step fails.

- [ ] **Step 1: Write failing validator tests**

Create `eldrin-workflows/worker/engine/ai/validate-schema.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { validateAgainstSchema } from './validate-schema';

const SCHEMA = {
  type: 'object',
  properties: {
    jobTitle: { type: 'string' },
    phones: { type: 'array', items: { type: 'string' } },
    social: { type: 'object' },
  },
  additionalProperties: false,
};

describe('validateAgainstSchema', () => {
  it('accepts a conforming object', () => {
    expect(
      validateAgainstSchema({ jobTitle: 'CTO', phones: ['+1 555'], social: {} }, SCHEMA),
    ).toEqual([]);
  });

  it('accepts omitted optional properties', () => {
    expect(validateAgainstSchema({}, SCHEMA)).toEqual([]);
  });

  it('rejects wrong property types', () => {
    const errs = validateAgainstSchema({ jobTitle: 42 }, SCHEMA);
    expect(errs).toHaveLength(1);
    expect(errs[0]).toContain('jobTitle');
  });

  it('rejects additional properties when additionalProperties is false', () => {
    expect(validateAgainstSchema({ hacker: true }, SCHEMA)).toHaveLength(1);
  });

  it('rejects wrong array item types', () => {
    expect(validateAgainstSchema({ phones: [1] }, SCHEMA)).toHaveLength(1);
  });

  it('enforces required fields', () => {
    const s = { type: 'object', properties: { a: { type: 'string' } }, required: ['a'] };
    expect(validateAgainstSchema({}, s)).toHaveLength(1);
  });

  it('rejects non-objects for type object', () => {
    expect(validateAgainstSchema('nope', SCHEMA)).toHaveLength(1);
  });
});
```

- [ ] **Step 2: Run to verify failure, then implement the validator**

Run: `cd eldrin-workflows && npx vitest run worker/engine/ai` — FAIL (module missing).

Create `eldrin-workflows/worker/engine/ai/validate-schema.ts`:

```ts
/**
 * Minimal JSON-schema validator for AI-extraction outputs. Deliberately
 * supports only the subset the shipped schemas use: type, properties,
 * required, items, additionalProperties:false. Returns human-readable
 * error strings; empty array means valid.
 */
export function validateAgainstSchema(
  value: unknown,
  schema: Record<string, unknown>,
  path = '$',
): string[] {
  const type = schema.type as string | undefined;

  if (type === 'object') {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return [`${path}: expected object`];
    }
    const errors: string[] = [];
    const props = (schema.properties ?? {}) as Record<string, Record<string, unknown>>;
    const required = (schema.required ?? []) as string[];
    const record = value as Record<string, unknown>;

    for (const key of required) {
      if (record[key] === undefined) errors.push(`${path}.${key}: required`);
    }
    for (const [key, propValue] of Object.entries(record)) {
      const propSchema = props[key];
      if (!propSchema) {
        if (schema.additionalProperties === false) {
          errors.push(`${path}.${key}: additional property not allowed`);
        }
        continue;
      }
      if (propValue !== undefined && propValue !== null) {
        errors.push(...validateAgainstSchema(propValue, propSchema, `${path}.${key}`));
      }
    }
    return errors;
  }

  if (type === 'array') {
    if (!Array.isArray(value)) return [`${path}: expected array`];
    const itemSchema = schema.items as Record<string, unknown> | undefined;
    if (!itemSchema) return [];
    return value.flatMap((item, i) =>
      validateAgainstSchema(item, itemSchema, `${path}[${i}]`),
    );
  }

  if (type === 'string' && typeof value !== 'string') return [`${path}: expected string`];
  if (type === 'number' && typeof value !== 'number') return [`${path}: expected number`];
  if (type === 'boolean' && typeof value !== 'boolean') return [`${path}: expected boolean`];
  return [];
}
```

Run: `cd eldrin-workflows && npx vitest run worker/engine/ai` — Expected: PASS.

- [ ] **Step 3: Create provider types, registry, and the mock provider**

Create `eldrin-workflows/worker/engine/ai/types.ts`:

```ts
export interface ExtractRequest {
  prompt: string;
  input: string;
  schema: Record<string, unknown>;
  env: Record<string, unknown>;
}

export interface AiProvider {
  name: string;
  /** Returns the raw extraction result; the step validates it against schema. */
  extract(req: ExtractRequest): Promise<unknown>;
}
```

Create `eldrin-workflows/worker/engine/ai/providers/mock.ts`:

```ts
import type { AiProvider, ExtractRequest } from '../types';

const PHONE_RE = /(?:\+?\d[\d\s().-]{7,}\d)/g;
const LINKEDIN_RE = /https?:\/\/(?:[a-z]{2,3}\.)?linkedin\.com\/[^\s"'<>]+/i;
const TWITTER_RE = /https?:\/\/(?:www\.)?(?:twitter|x)\.com\/[^\s"'<>]+/i;
const GITHUB_RE = /https?:\/\/(?:www\.)?github\.com\/[^\s"'<>]+/i;
/** "Jane Doe, CTO at Acme" / "CTO, Acme Corp" / "VP of Sales | Acme" */
const TITLE_RE =
  /\b((?:Chief [A-Z][a-z]+ Officer|C[ETFOIM]O|VP(?: of [A-Z][a-z]+)?|(?:Senior |Lead |Head of )?[A-Z][a-z]+ (?:Manager|Director|Engineer|Officer|Consultant)))\b/;

/**
 * Deterministic extraction so the full pipeline is testable and demoable
 * with no LLM configured. Only emits keys the requested schema declares.
 */
export const mockProvider: AiProvider = {
  name: 'mock',
  async extract(req: ExtractRequest): Promise<unknown> {
    const props = ((req.schema.properties ?? {}) as Record<string, unknown>);
    const text = req.input;
    const result: Record<string, unknown> = {};

    if ('jobTitle' in props) {
      const title = text.match(TITLE_RE)?.[1];
      if (title) result.jobTitle = title;
    }
    if ('phones' in props) {
      const phones = [...new Set(text.match(PHONE_RE) ?? [])].map((p) => p.trim());
      if (phones.length > 0) result.phones = phones;
    }
    if ('companyName' in props) {
      const company = text.match(/\bat ([A-Z][A-Za-z0-9&. ]{1,40}?)(?=[\n,.|]|$)/)?.[1];
      if (company) result.companyName = company.trim();
    }
    if ('social' in props) {
      const social: Record<string, string> = {};
      const linkedin = text.match(LINKEDIN_RE)?.[0];
      const twitter = text.match(TWITTER_RE)?.[0];
      const github = text.match(GITHUB_RE)?.[0];
      if (linkedin) social.linkedin = linkedin;
      if (twitter) social.twitter = twitter;
      if (github) social.github = github;
      if (Object.keys(social).length > 0) result.social = social;
    }
    return result;
  },
};
```

Create `eldrin-workflows/worker/engine/ai/registry.ts`:

```ts
import type { AiProvider } from './types';
import { mockProvider } from './providers/mock';

const providers = new Map<string, AiProvider>();

export function registerAiProvider(provider: AiProvider): void {
  providers.set(provider.name, provider);
}

export function getAiProvider(name: string): AiProvider | undefined {
  return providers.get(name);
}

registerAiProvider(mockProvider);
```

- [ ] **Step 4: Write failing `ai_extract` step tests**

Create `eldrin-workflows/worker/engine/steps/ai-extract.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { aiExtractRunner } from './ai-extract';
import { registerAiProvider } from '../ai/registry';
import type { ExecutionContext } from '../types';

const SCHEMA = {
  type: 'object',
  properties: {
    jobTitle: { type: 'string' },
    phones: { type: 'array', items: { type: 'string' } },
    social: { type: 'object' },
  },
  additionalProperties: false,
};

function ctx(env: Record<string, unknown> = {}): ExecutionContext {
  return {
    workflowId: 'wf1',
    runId: 'run1',
    trigger: { type: 'event', data: {} },
    payload: {},
    steps: {},
    env,
  };
}

const EMAIL = `Best regards,
Jane Doe
Marketing Director at Acme Corp
+1 555 010 9999
https://www.linkedin.com/in/janedoe`;

describe('ai_extract', () => {
  it('runs the mock provider by default and returns validated output', async () => {
    const r = await aiExtractRunner.execute(
      { prompt: 'Extract contact details', input: EMAIL, schema: SCHEMA },
      ctx(),
    );
    expect(r.success).toBe(true);
    const out = r.output as Record<string, unknown>;
    expect(out.jobTitle).toBe('Marketing Director');
    expect(out.phones).toEqual(['+1 555 010 9999']);
    expect((out.social as Record<string, string>).linkedin).toContain('linkedin.com');
  });

  it('fails when required config is missing', async () => {
    const r = await aiExtractRunner.execute({ input: EMAIL, schema: SCHEMA }, ctx());
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/prompt/i);
  });

  it('fails when the provider is unknown', async () => {
    const r = await aiExtractRunner.execute(
      { provider: 'nope', prompt: 'p', input: EMAIL, schema: SCHEMA },
      ctx(),
    );
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/provider/i);
  });

  it('fails when provider output violates the schema', async () => {
    registerAiProvider({
      name: 'bad',
      extract: async () => ({ jobTitle: 42 }),
    });
    const r = await aiExtractRunner.execute(
      { provider: 'bad', prompt: 'p', input: EMAIL, schema: SCHEMA },
      ctx(),
    );
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/schema/i);
  });

  it('fails when the provider throws', async () => {
    registerAiProvider({
      name: 'boom',
      extract: async () => {
        throw new Error('LLM unavailable');
      },
    });
    const r = await aiExtractRunner.execute(
      { provider: 'boom', prompt: 'p', input: EMAIL, schema: SCHEMA },
      ctx(),
    );
    expect(r.success).toBe(false);
    expect(r.error).toContain('LLM unavailable');
  });

  it('respects env.AI_PROVIDER as the default provider', async () => {
    registerAiProvider({ name: 'envprov', extract: async () => ({}) });
    const r = await aiExtractRunner.execute(
      { prompt: 'p', input: EMAIL, schema: SCHEMA },
      ctx({ AI_PROVIDER: 'envprov' }),
    );
    expect(r.success).toBe(true);
    expect(r.output).toEqual({});
  });
});
```

Run: `cd eldrin-workflows && npx vitest run worker/engine/steps/ai-extract.test.ts`
Expected: FAIL — module missing.

- [ ] **Step 5: Implement the step**

Create `eldrin-workflows/worker/engine/steps/ai-extract.ts`:

```ts
import type { StepRunner, ExecutionContext, StepResult } from '../types';
import { getAiProvider } from '../ai/registry';
import { validateAgainstSchema } from '../ai/validate-schema';

const EXTRACT_TIMEOUT_MS = 30000;

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`ai_extract timed out after ${ms}ms`)), ms);
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

export const aiExtractRunner: StepRunner = {
  type: 'ai_extract',
  async execute(
    config: Record<string, unknown>,
    context: ExecutionContext,
  ): Promise<StepResult> {
    const prompt = config.prompt;
    const input = config.input;
    const schema = config.schema;

    if (typeof prompt !== 'string' || !prompt.trim()) {
      return { success: false, error: 'prompt is required' };
    }
    if (typeof input !== 'string' || !input.trim()) {
      return { success: false, error: 'input is required' };
    }
    if (typeof schema !== 'object' || schema === null || Array.isArray(schema)) {
      return { success: false, error: 'schema is required and must be an object' };
    }

    const providerName =
      (typeof config.provider === 'string' && config.provider) ||
      (typeof context.env.AI_PROVIDER === 'string' && context.env.AI_PROVIDER) ||
      'mock';
    const provider = getAiProvider(providerName);
    if (!provider) {
      return { success: false, error: `Unknown AI provider: ${providerName}` };
    }

    try {
      const raw = await withTimeout(
        provider.extract({
          prompt,
          input,
          schema: schema as Record<string, unknown>,
          env: context.env,
        }),
        EXTRACT_TIMEOUT_MS,
      );
      const errors = validateAgainstSchema(raw, schema as Record<string, unknown>);
      if (errors.length > 0) {
        return {
          success: false,
          error: `Provider output failed schema validation: ${errors.join('; ')}`,
        };
      }
      return { success: true, output: raw };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { success: false, error: `ai_extract (${providerName}) failed: ${message}` };
    }
  },
};
```

Register + allowlist:
- `eldrin-workflows/worker/engine/registry.ts`: `import { aiExtractRunner } from './steps/ai-extract';` + `registerStep(aiExtractRunner);`
- `eldrin-workflows/worker/validation.ts`: add `'ai_extract',` to `STEP_TYPES`.

- [ ] **Step 6: Run all tests**

Run: `cd eldrin-workflows && npx vitest run`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git -C eldrin-workflows add worker/engine/ai worker/engine/steps/ai-extract.ts worker/engine/steps/ai-extract.test.ts worker/engine/registry.ts worker/validation.ts
git -C eldrin-workflows commit -m "feat(engine): ai_extract step with provider registry, mock provider, schema validation"
```

---

### Task 5: `openai` and `claude` AI providers

Both are tested by stubbing `globalThis.fetch` (the Anthropic SDK uses global fetch by default on Workers/Node 20+).

**Files:**
- Create: `eldrin-workflows/worker/engine/ai/providers/openai.ts`, `eldrin-workflows/worker/engine/ai/providers/claude.ts`
- Modify: `eldrin-workflows/worker/engine/ai/registry.ts`, `eldrin-workflows/package.json` (add `@anthropic-ai/sdk`)
- Test: `eldrin-workflows/worker/engine/ai/providers/providers.test.ts`

**Interfaces:**
- Consumes: `AiProvider`/`ExtractRequest` from `../types` (Task 4).
- Produces: providers `openai` (env: `AI_OPENAI_BASE_URL` required, `AI_OPENAI_MODEL` required, `AI_OPENAI_API_KEY` optional — local Ollama/LM Studio need no key) and `claude` (env: `AI_CLAUDE_API_KEY` required, `AI_CLAUDE_MODEL` optional, default `claude-opus-4-8`).

- [ ] **Step 1: Install the Anthropic SDK**

```bash
cd eldrin-workflows && npm install @anthropic-ai/sdk && cd ..
```

- [ ] **Step 2: Write failing provider tests**

Create `eldrin-workflows/worker/engine/ai/providers/providers.test.ts`:

```ts
import { describe, it, expect, vi, afterEach } from 'vitest';
import { openaiProvider } from './openai';
import { claudeProvider } from './claude';
import type { ExtractRequest } from '../types';

const SCHEMA = { type: 'object', properties: { jobTitle: { type: 'string' } }, additionalProperties: false };

function req(env: Record<string, unknown>): ExtractRequest {
  return { prompt: 'Extract details', input: 'Jane Doe, CTO', schema: SCHEMA, env };
}

afterEach(() => vi.restoreAllMocks());

describe('openai provider', () => {
  const ENV = { AI_OPENAI_BASE_URL: 'http://localhost:11434/v1', AI_OPENAI_MODEL: 'gemma3' };

  it('POSTs a chat completion and parses the JSON content', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({ choices: [{ message: { content: '{"jobTitle":"CTO"}' } }] }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    );

    const out = await openaiProvider.extract(req(ENV));
    expect(out).toEqual({ jobTitle: 'CTO' });

    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://localhost:11434/v1/chat/completions');
    const body = JSON.parse(init.body as string);
    expect(body.model).toBe('gemma3');
    expect(body.response_format).toEqual({ type: 'json_object' });
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
  });

  it('sends a bearer token when AI_OPENAI_API_KEY is set', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ choices: [{ message: { content: '{}' } }] }), { status: 200 }),
    );
    await openaiProvider.extract(req({ ...ENV, AI_OPENAI_API_KEY: 'sk-x' }));
    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer sk-x');
  });

  it('throws on non-2xx responses', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('down', { status: 503 }));
    await expect(openaiProvider.extract(req(ENV))).rejects.toThrow(/503/);
  });

  it('throws when AI_OPENAI_BASE_URL is not configured', async () => {
    await expect(openaiProvider.extract(req({}))).rejects.toThrow(/AI_OPENAI_BASE_URL/);
  });
});

describe('claude provider', () => {
  it('calls the Anthropic Messages API with structured output and parses the text block', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          id: 'msg_1',
          type: 'message',
          role: 'assistant',
          model: 'claude-opus-4-8',
          content: [{ type: 'text', text: '{"jobTitle":"CTO"}' }],
          stop_reason: 'end_turn',
          usage: { input_tokens: 1, output_tokens: 1 },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    );

    const out = await claudeProvider.extract(req({ AI_CLAUDE_API_KEY: 'sk-ant-x' }));
    expect(out).toEqual({ jobTitle: 'CTO' });

    const request = fetchSpy.mock.calls[0][0] as Request | string;
    const url = typeof request === 'string' ? request : request.url;
    expect(url).toContain('/v1/messages');
  });

  it('throws when AI_CLAUDE_API_KEY is not configured', async () => {
    await expect(claudeProvider.extract(req({}))).rejects.toThrow(/AI_CLAUDE_API_KEY/);
  });
});
```

Run: `cd eldrin-workflows && npx vitest run worker/engine/ai/providers` — Expected: FAIL (modules missing).

- [ ] **Step 3: Implement the openai provider**

Create `eldrin-workflows/worker/engine/ai/providers/openai.ts`:

```ts
import type { AiProvider, ExtractRequest } from '../types';

/**
 * OpenAI-compatible chat-completions provider. Covers OpenAI itself AND any
 * local server speaking the same protocol (Ollama, LM Studio) — point
 * AI_OPENAI_BASE_URL at e.g. http://localhost:11434/v1 and omit the key.
 */
export const openaiProvider: AiProvider = {
  name: 'openai',
  async extract(req: ExtractRequest): Promise<unknown> {
    const baseUrl = typeof req.env.AI_OPENAI_BASE_URL === 'string'
      ? req.env.AI_OPENAI_BASE_URL.replace(/\/+$/, '')
      : '';
    if (!baseUrl) throw new Error('AI_OPENAI_BASE_URL is not configured');
    const model = typeof req.env.AI_OPENAI_MODEL === 'string' ? req.env.AI_OPENAI_MODEL : '';
    if (!model) throw new Error('AI_OPENAI_MODEL is not configured');
    const apiKey = typeof req.env.AI_OPENAI_API_KEY === 'string' ? req.env.AI_OPENAI_API_KEY : '';

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (apiKey) headers.Authorization = `Bearer ${apiKey}`;

    const system = `${req.prompt}\n\nRespond with ONLY a JSON object conforming to this JSON schema (omit fields you are not confident about):\n${JSON.stringify(req.schema)}`;

    const response = await fetch(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: req.input },
        ],
        response_format: { type: 'json_object' },
        stream: false,
      }),
    });

    if (!response.ok) {
      throw new Error(`OpenAI-compatible endpoint returned HTTP ${response.status}`);
    }
    const data = (await response.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const content = data.choices?.[0]?.message?.content;
    if (typeof content !== 'string') {
      throw new Error('OpenAI-compatible response had no message content');
    }
    return JSON.parse(content);
  },
};
```

- [ ] **Step 4: Implement the claude provider**

Create `eldrin-workflows/worker/engine/ai/providers/claude.ts`:

```ts
import Anthropic from '@anthropic-ai/sdk';
import type { AiProvider, ExtractRequest } from '../types';

const DEFAULT_MODEL = 'claude-opus-4-8';

/**
 * Anthropic provider using the official SDK (fetch-based; Workers-compatible).
 * Structured outputs (output_config.format json_schema) make the response
 * schema-enforced server-side; the step's validator still re-checks it.
 */
export const claudeProvider: AiProvider = {
  name: 'claude',
  async extract(req: ExtractRequest): Promise<unknown> {
    const apiKey = typeof req.env.AI_CLAUDE_API_KEY === 'string' ? req.env.AI_CLAUDE_API_KEY : '';
    if (!apiKey) throw new Error('AI_CLAUDE_API_KEY is not configured');
    const model = typeof req.env.AI_CLAUDE_MODEL === 'string' && req.env.AI_CLAUDE_MODEL
      ? req.env.AI_CLAUDE_MODEL
      : DEFAULT_MODEL;

    const client = new Anthropic({ apiKey });
    const message = await client.messages.create({
      model,
      max_tokens: 2048,
      output_config: { format: { type: 'json_schema', schema: req.schema } },
      messages: [{ role: 'user', content: `${req.prompt}\n\n${req.input}` }],
    });

    const text = message.content.find(
      (block): block is Anthropic.TextBlock => block.type === 'text',
    )?.text;
    if (!text) throw new Error('Claude response contained no text block');
    return JSON.parse(text);
  },
};
```

Note: structured outputs require `additionalProperties: false` on object schemas — the shipped extraction schema has it; the step passes `config.schema` through unchanged.

Register both — in `eldrin-workflows/worker/engine/ai/registry.ts`:

```ts
import { openaiProvider } from './providers/openai';
import { claudeProvider } from './providers/claude';
// … after registerAiProvider(mockProvider):
registerAiProvider(openaiProvider);
registerAiProvider(claudeProvider);
```

- [ ] **Step 5: Run all tests + typecheck**

Run: `cd eldrin-workflows && npx vitest run && npx tsc -b`
Expected: all pass, no type errors. (If `output_config` typing lags in the installed SDK version, cast the request object `as Anthropic.MessageCreateParamsNonStreaming` — do not switch to raw fetch.)

- [ ] **Step 6: Commit**

```bash
git -C eldrin-workflows add package.json package-lock.json worker/engine/ai
git -C eldrin-workflows commit -m "feat(engine): openai (incl. local Ollama) and claude AI providers"
```

---

### Task 6: `call_app_api` step + env plumbing

`call_app_api` is already in `validation.ts` STEP_TYPES — only the runner is missing. It routes through core's app proxy with the service secret (core-side support lands in Task 8; this step is independently testable with a mocked fetch).

**Files:**
- Create: `eldrin-workflows/worker/engine/steps/call-app-api.ts`
- Modify: `eldrin-workflows/worker/engine/registry.ts`, `eldrin-workflows/worker-configuration.d.ts`, `eldrin-workflows/.dev.vars.example` (create if absent)
- Test: `eldrin-workflows/worker/engine/steps/call-app-api.test.ts`

**Interfaces:**
- Produces: step type `call_app_api`; config `{appId: string, method?: string (default GET), path: string (leading '/'), body?: unknown, timeout?: number (default 15000)}`; target URL `${env.CORE_URL}/api/app/${appId}${path}`; headers `Content-Type: application/json` + `X-Eldrin-App-Secret: env.JWT_SECRET`; output `{statusCode, body}`; `success = response.ok`.
- Consumes: whole-value interpolation (Task 2) so `body` sub-values like `"{{steps.extract.output}}"` arrive as objects.

- [ ] **Step 1: Write failing tests**

Create `eldrin-workflows/worker/engine/steps/call-app-api.test.ts`:

```ts
import { describe, it, expect, vi, afterEach } from 'vitest';
import { callAppApiRunner } from './call-app-api';
import type { ExecutionContext } from '../types';

function ctx(env: Record<string, unknown> = {}): ExecutionContext {
  return {
    workflowId: 'wf1',
    runId: 'run1',
    trigger: { type: 'event', data: {} },
    payload: {},
    steps: {},
    env: { CORE_URL: 'http://localhost:4000', JWT_SECRET: 's3cret', ...env },
  };
}

afterEach(() => vi.restoreAllMocks());

describe('call_app_api', () => {
  it('POSTs through the core proxy with the service secret', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );

    const r = await callAppApiRunner.execute(
      {
        appId: 'eldrin-crm',
        method: 'POST',
        path: '/api/enhancement/companies/c1',
        body: { data: { name: 'Acme' }, source: 'workflow:test' },
      },
      ctx(),
    );

    expect(r.success).toBe(true);
    expect(r.output).toEqual({ statusCode: 200, body: { ok: true } });

    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://localhost:4000/api/app/eldrin-crm/api/enhancement/companies/c1');
    expect((init.headers as Record<string, string>)['X-Eldrin-App-Secret']).toBe('s3cret');
    expect(JSON.parse(init.body as string)).toEqual({
      data: { name: 'Acme' },
      source: 'workflow:test',
    });
  });

  it('fails (success=false) on non-2xx with statusCode in output', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: 'nope' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      }),
    );
    const r = await callAppApiRunner.execute(
      { appId: 'eldrin-crm', method: 'POST', path: '/api/x', body: {} },
      ctx(),
    );
    expect(r.success).toBe(false);
    expect(r.error).toContain('401');
    expect((r.output as Record<string, unknown>).statusCode).toBe(401);
  });

  it('fails without CORE_URL', async () => {
    const r = await callAppApiRunner.execute(
      { appId: 'a', path: '/api/x' },
      ctx({ CORE_URL: undefined }),
    );
    expect(r.success).toBe(false);
    expect(r.error).toContain('CORE_URL');
  });

  it('fails without JWT_SECRET', async () => {
    const r = await callAppApiRunner.execute(
      { appId: 'a', path: '/api/x' },
      ctx({ JWT_SECRET: undefined }),
    );
    expect(r.success).toBe(false);
    expect(r.error).toContain('JWT_SECRET');
  });

  it('validates appId and path', async () => {
    expect((await callAppApiRunner.execute({ path: '/x' }, ctx())).success).toBe(false);
    expect((await callAppApiRunner.execute({ appId: 'a', path: 'x' }, ctx())).success).toBe(false);
  });

  it('fails on network errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('ECONNREFUSED'));
    const r = await callAppApiRunner.execute({ appId: 'a', path: '/api/x' }, ctx());
    expect(r.success).toBe(false);
    expect(r.error).toContain('ECONNREFUSED');
  });
});
```

Run: `cd eldrin-workflows && npx vitest run worker/engine/steps/call-app-api.test.ts` — Expected: FAIL.

- [ ] **Step 2: Implement**

Create `eldrin-workflows/worker/engine/steps/call-app-api.ts`:

```ts
import type { StepRunner, ExecutionContext, StepResult } from '../types';

const DEFAULT_TIMEOUT_MS = 15000;

/**
 * Call another Eldrin app's API through core's app proxy, authenticated as a
 * service principal via the shared X-Eldrin-App-Secret header.
 */
export const callAppApiRunner: StepRunner = {
  type: 'call_app_api',
  async execute(
    config: Record<string, unknown>,
    context: ExecutionContext,
  ): Promise<StepResult> {
    const appId = config.appId;
    const path = config.path;
    if (typeof appId !== 'string' || !appId.trim()) {
      return { success: false, error: 'appId is required' };
    }
    if (typeof path !== 'string' || !path.startsWith('/')) {
      return { success: false, error: 'path is required and must start with "/"' };
    }
    const coreUrl = typeof context.env.CORE_URL === 'string'
      ? context.env.CORE_URL.replace(/\/+$/, '')
      : '';
    if (!coreUrl) return { success: false, error: 'CORE_URL is not configured' };
    const secret = typeof context.env.JWT_SECRET === 'string' ? context.env.JWT_SECRET : '';
    if (!secret) return { success: false, error: 'JWT_SECRET is not configured' };

    const method = (typeof config.method === 'string' ? config.method : 'GET').toUpperCase();
    const timeoutMs = typeof config.timeout === 'number' ? config.timeout : DEFAULT_TIMEOUT_MS;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(`${coreUrl}/api/app/${appId}${path}`, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'X-Eldrin-App-Secret': secret,
        },
        body:
          method !== 'GET' && config.body !== undefined
            ? JSON.stringify(config.body)
            : undefined,
        signal: controller.signal,
      });
      clearTimeout(timer);

      const contentType = response.headers.get('content-type') || '';
      const body = contentType.includes('application/json')
        ? await response.json()
        : await response.text();

      return {
        success: response.ok,
        output: { statusCode: response.status, body },
        error: response.ok ? undefined : `HTTP ${response.status}: ${response.statusText}`,
      };
    } catch (err) {
      clearTimeout(timer);
      const message = err instanceof Error ? err.message : 'call_app_api failed';
      return { success: false, error: message };
    }
  },
};
```

Register — in `eldrin-workflows/worker/engine/registry.ts`: `import { callAppApiRunner } from './steps/call-app-api';` + `registerStep(callAppApiRunner);`

- [ ] **Step 3: Env typing + example vars**

In `eldrin-workflows/worker-configuration.d.ts`, extend `Env`:

```ts
interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  /** JWT secret shared with eldrin-core for token verification */
  JWT_SECRET: string;
  /** Base URL of the eldrin-core shell (app proxy host), e.g. http://localhost:4000 */
  CORE_URL?: string;
  /** AI provider defaults for the ai_extract step */
  AI_PROVIDER?: string;
  AI_OPENAI_BASE_URL?: string;
  AI_OPENAI_MODEL?: string;
  AI_OPENAI_API_KEY?: string;
  AI_CLAUDE_MODEL?: string;
  AI_CLAUDE_API_KEY?: string;
}
```

Create (or update) `eldrin-workflows/.dev.vars.example` with placeholders only:

```
JWT_SECRET=replace-with-the-shared-dev-secret
CORE_URL=http://localhost:4000
# ai_extract providers: mock (default, no config) | openai | claude
AI_PROVIDER=mock
AI_OPENAI_BASE_URL=http://localhost:11434/v1
AI_OPENAI_MODEL=gemma3
AI_OPENAI_API_KEY=
AI_CLAUDE_MODEL=claude-opus-4-8
AI_CLAUDE_API_KEY=
```

Verify `.dev.vars` is gitignored: `grep -n "dev.vars" eldrin-workflows/.gitignore` — must match `.dev.vars` (not the `.example`).

- [ ] **Step 4: Run all tests + typecheck**

Run: `cd eldrin-workflows && npx vitest run && npx tsc -b`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git -C eldrin-workflows add worker/engine/steps/call-app-api.ts worker/engine/steps/call-app-api.test.ts worker/engine/registry.ts worker-configuration.d.ts .dev.vars.example
git -C eldrin-workflows commit -m "feat(engine): call_app_api step — service calls through the core app proxy"
```

---

### Task 7: bulk import route + the two shipped workflow templates

**Files:**
- Create: `eldrin-workflows/worker/__tests__/test-db.ts`, `eldrin-workflows/workflows-templates/crm-enrich-company.json`, `eldrin-workflows/workflows-templates/crm-extract-email-insights.json`
- Modify: `eldrin-workflows/worker/routes/workflows.ts`
- Test: `eldrin-workflows/worker/routes/workflows-import.test.ts`

**Interfaces:**
- Produces: `POST /api/workflows/import` body `{workflows: Array<{name, description?, definition}>}` → 201 `{results: Array<{name, status: 'created'|'skipped'|'error', workflowId?, errors?}>}`. Idempotent by workflow name. Imported workflows are `isActive: false`.
- Consumes: `validateWorkflowDefinition` from `../validation`, `workflows` table, `generateId`/`now` from `../utils` (same imports the existing create route uses).

- [ ] **Step 1: Create the test DB helper**

First check the migrations dir exists: `ls eldrin-workflows/migrations/` (the `generate:migrations` script reads it). Create `eldrin-workflows/worker/__tests__/test-db.ts` (mirrors eldrin-crm's proven harness):

```ts
import BetterSqlite3 from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import * as schema from '../db/schema';
import type { Database } from '../db';

const MIGRATIONS_DIR = path.resolve(__dirname, '../../migrations');

export function createTestDb(): Database {
  const sqlite = new BetterSqlite3(':memory:');
  const files = readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.sql'))
    .sort();
  for (const file of files) {
    sqlite.exec(readFileSync(path.join(MIGRATIONS_DIR, file), 'utf8'));
  }
  return drizzle(sqlite, { schema }) as unknown as Database;
}
```

- [ ] **Step 2: Write failing route tests**

Create `eldrin-workflows/worker/routes/workflows-import.test.ts`:

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { Hono } from 'hono';
import { createTestDb } from '../__tests__/test-db';
import type { Database } from '../db';
import { workflowRoutes } from './workflows';

const VALID_DEFINITION = {
  version: 1,
  trigger: { type: 'event', config: { eventType: 'company.created' } },
  steps: [{ name: 'noop', type: 'delay', config: { seconds: 0 } }],
};

function createApp(db: Database) {
  const app = new Hono<{ Bindings: Env; Variables: { db: Database } }>();
  app.use('*', async (c, next) => {
    c.set('db', db);
    await next();
  });
  app.route('/', workflowRoutes);
  return app;
}

async function importReq(app: ReturnType<typeof createApp>, body: unknown) {
  return app.request('/api/workflows/import', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe('POST /api/workflows/import', () => {
  let db: Database;
  let app: ReturnType<typeof createApp>;

  beforeEach(() => {
    db = createTestDb();
    app = createApp(db);
  });

  it('creates workflows as inactive', async () => {
    const res = await importReq(app, {
      workflows: [{ name: 'W1', description: 'd', definition: VALID_DEFINITION }],
    });
    expect(res.status).toBe(201);
    const { results } = (await res.json()) as { results: Array<Record<string, unknown>> };
    expect(results[0].status).toBe('created');

    const list = await app.request('/api/workflows');
    const data = (await list.json()) as { workflows: Array<{ name: string; isActive: boolean }> };
    const w1 = data.workflows.find((w) => w.name === 'W1');
    expect(w1?.isActive).toBe(false);
  });

  it('skips existing names on re-import (idempotent)', async () => {
    await importReq(app, { workflows: [{ name: 'W1', definition: VALID_DEFINITION }] });
    const res = await importReq(app, { workflows: [{ name: 'W1', definition: VALID_DEFINITION }] });
    const { results } = (await res.json()) as { results: Array<Record<string, unknown>> };
    expect(results[0].status).toBe('skipped');
  });

  it('reports per-item validation errors without aborting the batch', async () => {
    const res = await importReq(app, {
      workflows: [
        { name: 'Bad', definition: { version: 2 } },
        { name: 'Good', definition: VALID_DEFINITION },
      ],
    });
    const { results } = (await res.json()) as { results: Array<Record<string, unknown>> };
    expect(results[0].status).toBe('error');
    expect(results[1].status).toBe('created');
  });

  it('rejects a body without a workflows array', async () => {
    const res = await importReq(app, { nope: true });
    expect(res.status).toBe(400);
  });

  it('accepts both shipped template files', async () => {
    const { readFileSync } = await import('node:fs');
    const path = await import('node:path');
    const dir = path.resolve(__dirname, '../../workflows-templates');
    const templates = ['crm-enrich-company.json', 'crm-extract-email-insights.json'].map((f) =>
      JSON.parse(readFileSync(path.join(dir, f), 'utf8')),
    );
    const res = await importReq(app, { workflows: templates });
    const { results } = (await res.json()) as { results: Array<Record<string, unknown>> };
    expect(results.every((r) => r.status === 'created')).toBe(true);
  });
});
```

Note: if the existing list route's response shape differs from `{workflows: [...]}`, read `GET /api/workflows` in `workflows.ts:14-50` and adjust the first test's assertion to the actual envelope — do not change the route.

Run: `cd eldrin-workflows && npx vitest run worker/routes` — Expected: FAIL (404 on /import; missing template files).

- [ ] **Step 3: Implement the import route**

In `eldrin-workflows/worker/routes/workflows.ts`, after the `POST /api/workflows` create route, add:

```ts
// POST /api/workflows/import — bulk, idempotent-by-name template seeding.
// Existing names are skipped so re-running an import never duplicates.
workflowRoutes.post('/api/workflows/import', async (c) => {
  const db = c.get('db');

  let body: { workflows?: Array<{ name?: string; description?: string; definition?: unknown }> };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  if (!Array.isArray(body.workflows) || body.workflows.length === 0) {
    return c.json({ error: 'Body must be { workflows: [{ name, definition }, ...] }' }, 400);
  }

  const results: Array<Record<string, unknown>> = [];
  for (const item of body.workflows) {
    const name = item.name?.trim();
    if (!name) {
      results.push({ name: item.name ?? null, status: 'error', errors: [{ field: 'name', message: 'Name is required' }] });
      continue;
    }
    const errors = validateWorkflowDefinition(item.definition);
    if (errors.length > 0) {
      results.push({ name, status: 'error', errors });
      continue;
    }
    const [existing] = await db
      .select({ id: workflows.id })
      .from(workflows)
      .where(eq(workflows.name, name));
    if (existing) {
      results.push({ name, status: 'skipped', workflowId: existing.id });
      continue;
    }
    const id = generateId();
    const timestamp = now();
    await db.insert(workflows).values({
      id,
      name,
      description: item.description?.trim() || null,
      definition: JSON.stringify(item.definition),
      isActive: false,
      createdBy: 'import',
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    results.push({ name, status: 'created', workflowId: id });
  }

  return c.json({ results }, 201);
});
```

(`validateWorkflowDefinition`, `workflows`, `eq`, `generateId`, `now` are already imported at the top of this file for the create route — verify and reuse.)

- [ ] **Step 4: Create the two template files**

Create `eldrin-workflows/workflows-templates/crm-enrich-company.json`:

```json
{
  "name": "CRM: Enrich new company",
  "description": "When the CRM auto-creates a provisional company from an inbound email domain, fetch the company homepage, extract title/meta/OG metadata, and apply it to the company record (fill-empty-only).",
  "definition": {
    "version": 1,
    "trigger": { "type": "event", "config": { "eventType": "company.created" } },
    "conditions": [
      { "field": "payload.isAutoCreated", "operator": "equals", "value": true }
    ],
    "steps": [
      {
        "name": "fetch_site",
        "type": "http_request",
        "config": { "url": "https://{{payload.domain}}", "timeout": 5000 }
      },
      {
        "name": "extract",
        "type": "html_extract",
        "config": {
          "html": "{{steps.fetch_site.output.body}}",
          "baseUrl": "https://{{payload.domain}}"
        }
      },
      {
        "name": "apply",
        "type": "call_app_api",
        "config": {
          "appId": "eldrin-crm",
          "method": "POST",
          "path": "/api/enhancement/companies/{{payload.companyId}}",
          "body": {
            "data": "{{steps.extract.output}}",
            "source": "workflow:enrich-company"
          }
        }
      }
    ]
  }
}
```

Create `eldrin-workflows/workflows-templates/crm-extract-email-insights.json`:

```json
{
  "name": "CRM: Extract email insights",
  "description": "When the CRM requests AI extraction for a captured email (unknown sender or low confidence), run the configured AI provider over the body text and apply the insights to the contact (fill-empty-only).",
  "definition": {
    "version": 1,
    "trigger": { "type": "event", "config": { "eventType": "email.extraction.requested" } },
    "steps": [
      {
        "name": "extract",
        "type": "ai_extract",
        "config": {
          "prompt": "Extract the sender's contact details from this email. Return ONLY fields you are confident about; omit anything uncertain.",
          "input": "{{payload.bodyText}}",
          "schema": {
            "type": "object",
            "properties": {
              "jobTitle": { "type": "string" },
              "phones": { "type": "array", "items": { "type": "string" } },
              "companyName": { "type": "string" },
              "social": { "type": "object" }
            },
            "additionalProperties": false
          }
        }
      },
      {
        "name": "apply",
        "type": "call_app_api",
        "config": {
          "appId": "eldrin-crm",
          "method": "POST",
          "path": "/api/enhancement/contacts/{{payload.contactId}}",
          "body": {
            "messageId": "{{payload.messageId}}",
            "insights": "{{steps.extract.output}}",
            "source": "workflow:extract-email-insights"
          }
        }
      }
    ]
  }
}
```

Check the `equals` operator exists in `validation.ts` `CONDITION_OPERATORS` (lines 18-33) — it should; if the operator list uses a different spelling (e.g. `eq`), use that spelling in the template.

- [ ] **Step 5: Run all tests + typecheck; commit**

Run: `cd eldrin-workflows && npx vitest run && npx tsc -b`
Expected: pass, including the "accepts both shipped template files" test (proves the templates validate against the real validator).

```bash
git -C eldrin-workflows add worker/routes/workflows.ts worker/routes/workflows-import.test.ts worker/__tests__/test-db.ts workflows-templates
git -C eldrin-workflows commit -m "feat: bulk idempotent workflow import + CRM enrichment/extraction templates"
```

---

### Task 8: eldrin-core — app proxy accepts the service secret

The proxy (`handleAppApiProxy` in `core/routes/apps.ts:714`) authorizes purely on the user JWT today, with an admin bypass at line ~765. Add a service-principal branch: a request bearing a valid `X-Eldrin-App-Secret` skips the route-permission check (like admins); an INVALID secret is rejected 401 (matching the event-endpoint behavior in `core/app.ts:232-242`). Incoming headers already forward to the target app (`new Headers(request.headers)`), so the secret reaches the receiving app unchanged.

**Files:**
- Create: `eldrin-core/core/auth/service-secret.ts`
- Modify: `eldrin-core/core/app.ts` (use the shared helper; delete the local copy), `eldrin-core/core/routes/apps.ts`
- Test: `eldrin-core/core/app.test.ts` (extend)

**Interfaces:**
- Produces: `isValidServiceSecret(header: string, jwtSecret: string | undefined): boolean` exported from `core/auth/service-secret.ts`; proxy behavior — valid secret → service principal (permission checks skipped), invalid secret → 401 `{error: 'Invalid service secret'}`, no secret → existing JWT flow unchanged.

- [ ] **Step 1: Create the branch and write failing tests**

```bash
git -C eldrin-core checkout -b feature/service-principal-proxy
```

Append to `eldrin-core/core/app.test.ts` (inside/near the existing "app API proxy path-join" describe — reuse its harness style):

```ts
describe('app API proxy service principal', () => {
  async function callProxy(headers: Record<string, string>) {
    const { handleAppApiProxy } = await import('./routes/apps');
    const { MockDatabaseAdapter } = await import('./test-utils/mock-db');

    const db = new MockDatabaseAdapter();
    // default_api_policy 'deny' + no declared routes: only admins or a valid
    // service secret can pass the permission gate.
    db.onQuery('FROM platform_apps', () => [
      { app_url: 'http://localhost:4009', developer_id: 'dev', default_api_policy: 'deny' },
    ]);
    db.onQuery('FROM app_api_routes', () => []);

    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response('{}', { status: 200 }));

    const response = await handleAppApiProxy(
      new Request('http://localhost:4000/api/app/eldrin-crm/enhancement/pending', { headers }),
      db as unknown as Parameters<typeof handleAppApiProxy>[1],
      'eldrin-crm',
      '/enhancement/pending',
      undefined,          // no user JWT
      'test-secret-for-app-tests',
    );
    return { response, fetchSpy };
  }

  it('forwards when a valid X-Eldrin-App-Secret is presented', async () => {
    const { response, fetchSpy } = await callProxy({
      'X-Eldrin-App-Secret': 'test-secret-for-app-tests',
    });
    expect(response.status).toBe(200);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    // The secret header passes through to the target app.
    const forwarded = fetchSpy.mock.calls[0][0] as Request;
    expect(forwarded.headers.get('X-Eldrin-App-Secret')).toBe('test-secret-for-app-tests');
    fetchSpy.mockRestore();
  });

  it('rejects an invalid secret with 401 and does not forward', async () => {
    const { response, fetchSpy } = await callProxy({ 'X-Eldrin-App-Secret': 'wrong' });
    expect(response.status).toBe(401);
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it('keeps the JWT path: no secret and no auth payload is forbidden', async () => {
    const { response, fetchSpy } = await callProxy({});
    expect(response.status).toBe(403);
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });
});
```

Run: `cd eldrin-core && npx vitest run core/app.test.ts -t "service principal"`
Expected: FAIL — valid-secret case returns 403.

- [ ] **Step 2: Extract the shared helper**

Create `eldrin-core/core/auth/service-secret.ts`:

```ts
/**
 * Validate the shared service-to-service secret sent by app workers.
 *
 * Plain equality is sufficient for the single-tenant platform today; kept in
 * one helper so it can be swapped for an HMAC-based scheme later.
 */
export function isValidServiceSecret(
  header: string,
  jwtSecret: string | undefined,
): boolean {
  return Boolean(jwtSecret) && header === jwtSecret;
}
```

In `eldrin-core/core/app.ts`: delete the local `isValidServiceSecret` function (lines ~206-214) and add `import { isValidServiceSecret } from './auth/service-secret';`. (Do NOT import from `app.ts` in `apps.ts` — `app.ts` already imports `apps.ts`; the standalone module avoids the cycle.)

- [ ] **Step 3: Add the service branch to the proxy**

In `eldrin-core/core/routes/apps.ts`: add `import { isValidServiceSecret } from '../auth/service-secret';` at the top. Inside `handleAppApiProxy`, right after the `routePath` computation (~line 751) and before the "Get user's permissions" block, insert:

```ts
    // --- Service principal: trusted worker-to-worker calls (e.g. a workflow's
    // call_app_api step). A valid shared secret skips route-permission checks
    // the same way platform admins do; an invalid one is rejected outright.
    const serviceSecretHeader = request.headers.get('X-Eldrin-App-Secret');
    let isService = false;
    if (serviceSecretHeader !== null) {
      if (!isValidServiceSecret(serviceSecretHeader, jwtSecret)) {
        return jsonResponse({ error: 'Invalid service secret' }, 401);
      }
      isService = true;
    }
```

Then change the permission gate condition from `if (!isAdmin) {` to:

```ts
    if (!isAdmin && !isService) {
```

- [ ] **Step 4: Run the core suite**

Run: `cd eldrin-core && npx vitest run core/app.test.ts`
Expected: all pass, including the pre-existing service-secret middleware tests (lines 132-183) which now exercise the shared helper.

- [ ] **Step 5: Commit**

```bash
git -C eldrin-core add core/auth/service-secret.ts core/app.ts core/routes/apps.ts core/app.test.ts
git -C eldrin-core commit -m "feat(proxy): accept X-Eldrin-App-Secret as a service principal on the app proxy"
```

---

### Task 9: eldrin-crm — migration + drizzle schema for AI-enhancement flags and provisional companies

**Files:**
- Create: `eldrin-crm/migrations/20260216900000-ai-enhancement.sql`
- Modify: `eldrin-crm/worker/db/schema.ts`
- Test: `eldrin-crm/worker/__tests__/schema-ai-enhancement.test.ts`

**Interfaces:**
- Produces (drizzle columns; later tasks depend on these exact names):
  - `contacts.aiEnhancementStatus` (`ai_enhancement_status` TEXT, nullable: `null | 'pending' | 'enhanced'`), `contacts.aiEnhancementUpdatedAt` (`ai_enhancement_updated_at` INTEGER)
  - `companies.aiEnhancementStatus`, `companies.aiEnhancementUpdatedAt` (same shapes)
  - `companies.isAutoCreated` (`is_auto_created` INTEGER NOT NULL DEFAULT 0, boolean mode), `companies.captureConfidence` (`capture_confidence` REAL), `companies.captureSource` (`capture_source` TEXT)

- [ ] **Step 1: Write the failing schema test**

The CRM branch is already `feature/phase-07-email-integration` — verify with `git -C eldrin-crm branch --show-current`.

Create `eldrin-crm/worker/__tests__/schema-ai-enhancement.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { eq } from 'drizzle-orm';
import { createTestDb } from './test-db';
import { contacts, companies } from '../db';

const T0 = 1700000000000;

describe('ai-enhancement schema', () => {
  it('stores the enhancement flag on contacts', async () => {
    const db = createTestDb();
    await db.insert(contacts).values({
      id: 'c1',
      firstName: 'Jane',
      lastName: 'Doe',
      aiEnhancementStatus: 'pending',
      aiEnhancementUpdatedAt: T0,
      createdBy: 'system',
      createdAt: T0,
      updatedAt: T0,
    });
    const [row] = await db.select().from(contacts).where(eq(contacts.id, 'c1'));
    expect(row.aiEnhancementStatus).toBe('pending');
  });

  it('stores auto-capture + enhancement columns on companies', async () => {
    const db = createTestDb();
    await db.insert(companies).values({
      id: 'co1',
      name: 'acme.com',
      domain: 'acme.com',
      isAutoCreated: true,
      captureConfidence: 0.3,
      captureSource: 'email-auto-capture',
      aiEnhancementStatus: 'pending',
      aiEnhancementUpdatedAt: T0,
      createdBy: 'system',
      createdAt: T0,
      updatedAt: T0,
    });
    const [row] = await db.select().from(companies).where(eq(companies.id, 'co1'));
    expect(row.isAutoCreated).toBe(true);
    expect(row.aiEnhancementStatus).toBe('pending');
  });
});
```

Run: `cd eldrin-crm && npx vitest run worker/__tests__/schema-ai-enhancement.test.ts`
Expected: FAIL — unknown columns.

- [ ] **Step 2: Create the migration**

Create `eldrin-crm/migrations/20260216900000-ai-enhancement.sql` (filename MUST keep the 14-digit prefix — see Global Constraints):

```sql
-- Phase 10 slice 3: AI enhancement.
-- ai_enhancement_status is the durable source of truth for AI processing:
-- NULL = nothing to do, 'pending' = material awaits processing (armed at
-- capture; failures never transition it), 'enhanced' = an apply endpoint
-- succeeded. Companies also become auto-creatable (provisional records
-- from inbound email domains), mirroring the slice-1 contact columns.

ALTER TABLE contacts ADD COLUMN ai_enhancement_status TEXT;
ALTER TABLE contacts ADD COLUMN ai_enhancement_updated_at INTEGER;

ALTER TABLE companies ADD COLUMN ai_enhancement_status TEXT;
ALTER TABLE companies ADD COLUMN ai_enhancement_updated_at INTEGER;
ALTER TABLE companies ADD COLUMN is_auto_created INTEGER NOT NULL DEFAULT 0;
ALTER TABLE companies ADD COLUMN capture_confidence REAL;
ALTER TABLE companies ADD COLUMN capture_source TEXT;

CREATE INDEX idx_contacts_ai_status ON contacts(ai_enhancement_status);
CREATE INDEX idx_companies_ai_status ON companies(ai_enhancement_status);
CREATE INDEX idx_companies_auto_created ON companies(is_auto_created);
```

- [ ] **Step 3: Extend the drizzle schema**

In `eldrin-crm/worker/db/schema.ts`, inside the `contacts` table definition (after `captureSource`):

```ts
    // AI enhancement (Phase 10 slice 3): pending = material awaits AI
    // processing; enhanced = an apply endpoint succeeded. Failures never
    // transition the flag — pending persists for retry / pull processing.
    aiEnhancementStatus: text('ai_enhancement_status'),
    aiEnhancementUpdatedAt: integer('ai_enhancement_updated_at', { mode: 'number' }),
```

Inside `companies` (after `ownerId`):

```ts
    // Auto-capture (Phase 10 slice 3): provisional companies created from
    // inbound email domains, awaiting enrichment + user confirmation.
    isAutoCreated: integer('is_auto_created', { mode: 'boolean' }).notNull().default(false),
    captureConfidence: real('capture_confidence'),
    captureSource: text('capture_source'),
    aiEnhancementStatus: text('ai_enhancement_status'),
    aiEnhancementUpdatedAt: integer('ai_enhancement_updated_at', { mode: 'number' }),
```

Add to the contacts index array: `index('idx_contacts_ai_status').on(table.aiEnhancementStatus),`
Add to the companies index array: `index('idx_companies_ai_status').on(table.aiEnhancementStatus), index('idx_companies_auto_created').on(table.isAutoCreated),`

(`real` is already imported in schema.ts for `captureConfidence` on contacts — verify the import list includes `real`.)

- [ ] **Step 4: Regenerate embedded migrations, run tests**

```bash
cd eldrin-crm && npm run generate:migrations && npx vitest run && npx tsc -b
```
Expected: all tests pass (the test-db harness replays the real migrations dir, so the new SQL is exercised), typecheck clean.

- [ ] **Step 5: Commit**

```bash
git -C eldrin-crm add migrations/20260216900000-ai-enhancement.sql worker/db/schema.ts worker/migrations.generated.ts worker/__tests__/schema-ai-enhancement.test.ts
git -C eldrin-crm commit -m "feat(schema): ai_enhancement_status flags + provisional-company columns"
```

---

### Task 10: eldrin-crm — persist `bodyText` in email-activity metadata

Today `createEmailActivity` stores only the 200-char `snippet` (`email-linking.ts:220-224`); `bodyText` is used for signature parsing then dropped. The pull model needs the body retrievable later.

**Files:**
- Modify: `eldrin-crm/worker/services/email-linking.ts`
- Test: `eldrin-crm/worker/__tests__/email-linking.test.ts` (extend)

**Interfaces:**
- Produces: `EmailActivityMetadata.bodyText?: string`; `EmailActivityInput.bodyText?: string | null`; inbound email activities carry `bodyText` in their metadata JSON. Task 12's pending/material endpoints read `JSON.parse(activities.metadata).bodyText`.

- [ ] **Step 1: Write the failing test**

Append to `eldrin-crm/worker/__tests__/email-linking.test.ts` (reuse its existing imports/harness — it already imports `createTestDb`, service functions, and the `activities` table; follow the file's established fixture style for contacts/emails):

```ts
it('persists bodyText in the activity metadata for pull-based processing', async () => {
  const db = createTestDb();
  await seedContactWithEmail(db, 'c1', 'jane@acme.com'); // reuse/adapt the file's existing seed helper
  await processInboundEmail(db, {
    messageId: 'm-body-1',
    from: 'jane@acme.com',
    to: ['me@mycrm.com'],
    subject: 'Hello',
    snippet: 'short snippet',
    bodyText: 'Full body with a signature\nJane Doe\nCTO at Acme',
    receivedAt: 1700000000000,
  });
  const [activity] = await db
    .select()
    .from(activities)
    .where(eq(activities.sourceMessageId, 'm-body-1'));
  const metadata = JSON.parse(activity.metadata as string);
  expect(metadata.bodyText).toContain('CTO at Acme');
  expect(metadata.snippet).toBe('short snippet');
});
```

If the file has no seed helper, seed inline exactly as the file's other tests do (insert into `contacts` + `contactEmails`). If `processInboundEmail`'s payload field names differ (check `InboundEmailPayload` at `email-linking.ts:36-49`), match them.

Run: `cd eldrin-crm && npx vitest run worker/__tests__/email-linking.test.ts`
Expected: FAIL — `metadata.bodyText` undefined.

- [ ] **Step 2: Implement**

In `eldrin-crm/worker/services/email-linking.ts`:

1. `EmailActivityMetadata` (line ~79): add `bodyText?: string;` after `snippet?: string;`
2. `EmailActivityInput` (line ~61): add `bodyText?: string | null;`
3. In `createEmailActivity`'s metadata build (line ~220):

```ts
  const metadata: EmailActivityMetadata = {
    direction: input.direction,
    from: extractAddress(input.from),
    to: input.to.map(extractAddress),
    ...(input.snippet ? { snippet: input.snippet } : {}),
    ...(input.bodyText ? { bodyText: input.bodyText } : {}),
  };
```

4. Find every `createEmailActivity(` call site inside this file (the inbound path in `processInboundEmail`, and the outbound path if it builds an `EmailActivityInput`) and pass `bodyText: payload.bodyText ?? null` where the payload carries it.

- [ ] **Step 3: Run tests + commit**

Run: `cd eldrin-crm && npx vitest run` — Expected: all pass.

```bash
git -C eldrin-crm add worker/services/email-linking.ts worker/__tests__/email-linking.test.ts
git -C eldrin-crm commit -m "feat(email): persist bodyText in activity metadata for pull-based AI processing"
```

---

### Task 11: eldrin-crm — company auto-creation, flag arming, new events

**Files:**
- Modify: `eldrin-crm/worker/services/auto-capture.ts`, `eldrin-crm/worker/services/event-emitter.ts`, `eldrin-crm/worker/routes/events.ts`, `eldrin-crm/worker/routes/companies.ts`, `eldrin-crm/public/eldrin-app.manifest.json`
- Test: `eldrin-crm/worker/__tests__/auto-capture.test.ts` (extend; if capture tests live in a differently-named file, extend that one)

**Interfaces:**
- Produces:
  - `isEnrichableDomain(domain: string): boolean` (exported from auto-capture.ts) — false for freemail, IPs, localhost/.local/.internal/.lan, malformed hostnames.
  - `InboundCaptureOutcome` extended with: `contactId: string | null`, `captureConfidence: number | null`, `companyAutoCreated: boolean`, `autoCreatedCompanyId: string | null`, `companyDomain: string | null`.
  - Provisional company rows: `{name: domain, domain, isAutoCreated: true, captureConfidence: 0.3, captureSource: 'email-auto-capture', aiEnhancementStatus: 'pending'}`.
  - Contact flag arming: any captured inbound email with non-null `bodyText` sets the sender contact's `aiEnhancementStatus = 'pending'` (also re-arms `enhanced` contacts — new material).
  - New emitters: `emitCompanyCreated(env, {companyId, domain, isAutoCreated})`, `emitEmailExtractionRequested(env, {messageId, contactId, from, bodyText})`.
  - Event conditions (in the webhook route): `company.created` emitted when a provisional company was created (and on manual company POST with `isAutoCreated: false`); `email.extraction.requested` emitted when `bodyText` is present AND (`contactAutoCreated` OR stored `captureConfidence < 0.7`).
  - `PATCH /api/companies/:id` accepts `isAutoCreated` (Confirm action parity with contacts).

- [ ] **Step 1: Write failing tests**

Append to the auto-capture test file (check `ls eldrin-crm/worker/__tests__/` for the exact name; follow its harness):

```ts
describe('isEnrichableDomain', () => {
  it.each(['gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com'])(
    'rejects freemail domain %s',
    (d) => expect(isEnrichableDomain(d)).toBe(false),
  );
  it.each(['192.168.1.10', 'localhost', 'intranet.local', 'srv.internal', 'box.lan', 'no_dots', 'bad domain.com'])(
    'rejects non-enrichable host %s',
    (d) => expect(isEnrichableDomain(d)).toBe(false),
  );
  it.each(['acme.com', 'sub.acme-corp.io', 'ACME.COM'])(
    'accepts corporate domain %s',
    (d) => expect(isEnrichableDomain(d)).toBe(true),
  );
});

describe('captureInboundSender — provisional companies + flag arming', () => {
  it('auto-creates a pending provisional company for an unknown corporate domain', async () => {
    const db = createTestDb();
    const outcome = await captureInboundSender(db, {
      from: 'Jane Doe <jane@newcorp.com>',
      to: ['me@mycrm.com'],
      snippet: 'hi',
      bodyText: 'Hello\nJane Doe\nCTO at NewCorp\n+1 555 010 1234',
    });
    expect(outcome.contactAutoCreated).toBe(true);
    expect(outcome.companyAutoCreated).toBe(true);
    expect(outcome.companyDomain).toBe('newcorp.com');

    const [company] = await db
      .select()
      .from(companies)
      .where(eq(companies.id, outcome.autoCreatedCompanyId!));
    expect(company.name).toBe('newcorp.com');
    expect(company.isAutoCreated).toBe(true);
    expect(company.aiEnhancementStatus).toBe('pending');

    const [contact] = await db
      .select()
      .from(contacts)
      .where(eq(contacts.id, outcome.contactId!));
    expect(contact.aiEnhancementStatus).toBe('pending');
  });

  it('does not create a company for freemail senders', async () => {
    const db = createTestDb();
    const outcome = await captureInboundSender(db, {
      from: 'Bob <bob@gmail.com>',
      to: ['me@mycrm.com'],
      snippet: 'hi',
      bodyText: 'hello there',
    });
    expect(outcome.companyAutoCreated).toBe(false);
    const rows = await db.select().from(companies);
    expect(rows).toHaveLength(0);
  });

  it('does not award the company-match confidence bonus for a just-created company', async () => {
    const db = createTestDb();
    const outcome = await captureInboundSender(db, {
      from: 'Jane Doe <jane@newcorp.com>',
      to: ['me@mycrm.com'],
      snippet: 'hi',
      bodyText: 'body',
    });
    // display-name yes (0.3+0.4), created company corroborates nothing (no +0.2)
    expect(outcome.captureConfidence).toBe(0.7);
  });

  it('re-arms an enhanced contact when new mail with bodyText arrives', async () => {
    const db = createTestDb();
    const first = await captureInboundSender(db, {
      from: 'jane@newcorp.com', to: ['me@mycrm.com'], snippet: 's', bodyText: 'b1',
    });
    await db.update(contacts)
      .set({ aiEnhancementStatus: 'enhanced' })
      .where(eq(contacts.id, first.contactId!));
    await captureInboundSender(db, {
      from: 'jane@newcorp.com', to: ['me@mycrm.com'], snippet: 's', bodyText: 'b2',
    });
    const [contact] = await db.select().from(contacts).where(eq(contacts.id, first.contactId!));
    expect(contact.aiEnhancementStatus).toBe('pending');
  });

  it('does not arm the flag when there is no bodyText', async () => {
    const db = createTestDb();
    const outcome = await captureInboundSender(db, {
      from: 'jane@newcorp.com', to: ['me@mycrm.com'], snippet: 'only snippet', bodyText: null,
    });
    const [contact] = await db.select().from(contacts).where(eq(contacts.id, outcome.contactId!));
    expect(contact.aiEnhancementStatus).toBeNull();
  });
});
```

Adjust imports at the top of the test file: `isEnrichableDomain`, `captureInboundSender` from `../services/auto-capture`; `companies`, `contacts` from `../db`. Run — Expected: FAIL.

- [ ] **Step 2: Implement in `auto-capture.ts`**

Add near the confidence constants:

```ts
/**
 * Freemail domains never become provisional companies — a person's private
 * mailbox is not an organisation. Static list; extend as needed.
 */
const FREEMAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com',
  'msn.com', 'yahoo.com', 'ymail.com', 'icloud.com', 'me.com', 'mac.com',
  'aol.com', 'proton.me', 'protonmail.com', 'gmx.com', 'gmx.de', 'gmx.net',
  'web.de', 'mail.com', 'zoho.com', 'yandex.com', 'yandex.ru', 'fastmail.com',
  'hey.com', 'tutanota.com', 'tuta.io', 'pm.me', 'freemail.hu', 'citromail.hu',
  't-online.de', 'orange.fr', 'wanadoo.fr',
]);

const HOSTNAME_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * SSRF guard + noise filter: only plausible public corporate hostnames become
 * provisional companies (their domain later feeds an http_request step).
 */
export function isEnrichableDomain(domain: string): boolean {
  const d = domain.trim().toLowerCase();
  if (!d || FREEMAIL_DOMAINS.has(d)) return false;
  if (IPV4_RE.test(d)) return false;
  if (d === 'localhost' || d.endsWith('.local') || d.endsWith('.internal') || d.endsWith('.lan')) {
    return false;
  }
  return HOSTNAME_RE.test(d);
}
```

Add the company creator (near `autoCreateContactFromEmail`; reuse the file's existing `generateId`/`now` helpers and `companies` import from `../db`):

```ts
async function autoCreateCompanyFromDomain(
  db: Database,
  domain: string,
): Promise<{ companyId: string }> {
  const companyId = generateId();
  const timestamp = now();
  await db.insert(companies).values({
    id: companyId,
    name: domain, // placeholder until enrichment fills the real name
    domain,
    isAutoCreated: true,
    captureConfidence: CONFIDENCE_BASE,
    captureSource: 'email-auto-capture',
    aiEnhancementStatus: 'pending',
    aiEnhancementUpdatedAt: timestamp,
    createdBy: 'system',
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  return { companyId };
}
```

In `autoCreateContactFromEmail` (the block around lines 137-188): after `const company = await matchEmailToCompany(db, address);` insert company auto-creation, and change the confidence call so a just-created company earns no bonus:

```ts
  let company = await matchEmailToCompany(db, address);
  let companyAutoCreated = false;
  let autoCreatedCompanyId: string | null = null;
  const domain = address.split('@')[1]?.toLowerCase() ?? '';
  if (!company && isEnrichableDomain(domain)) {
    const created = await autoCreateCompanyFromDomain(db, domain);
    companyAutoCreated = true;
    autoCreatedCompanyId = created.companyId;
    company = { companyId: created.companyId } as NonNullable<typeof company>;
  }
  const confidence = computeCaptureConfidence({
    hasDisplayName: name.fromDisplayName,
    // A shell company we just invented corroborates nothing.
    companyMatched: company !== null && !companyAutoCreated,
  });
```

Extend `AutoCreateResult` and the function's return to carry `{contactId, created, confidence, companyAutoCreated, autoCreatedCompanyId, companyDomain: companyAutoCreated ? domain : null}` (add the new fields to the interface; thread them through the existing return statement).

In `captureInboundSender` (lines 279-317): extend `InboundCaptureOutcome`:

```ts
export interface InboundCaptureOutcome {
  contactAutoCreated: boolean;
  autoCreatedContactId: string | null;
  signatureApplied: boolean;
  contactId: string | null;
  captureConfidence: number | null;
  companyAutoCreated: boolean;
  autoCreatedCompanyId: string | null;
  companyDomain: string | null;
}
```

Update `NO_CAPTURE` with the new fields (`contactId: null, captureConfidence: null, companyAutoCreated: false, autoCreatedCompanyId: null, companyDomain: null`). In the function body: capture the extended `AutoCreateResult` fields when a contact is auto-created; for a matched pre-existing contact, read its stored confidence:

```ts
  let captureConfidence: number | null = null;
  let companyAutoCreated = false;
  let autoCreatedCompanyId: string | null = null;
  let companyDomain: string | null = null;

  if (!contactId) {
    if (!shouldAutoCreateFromInbound(payload.from, payload.to)) return NO_CAPTURE;
    const result = await autoCreateContactFromEmail(db, { from: payload.from });
    if (!result) return NO_CAPTURE;
    contactId = result.contactId;
    created = result.created;
    captureConfidence = result.confidence;
    companyAutoCreated = result.companyAutoCreated;
    autoCreatedCompanyId = result.autoCreatedCompanyId;
    companyDomain = result.companyDomain;
  } else {
    const [existing] = await db
      .select({ captureConfidence: contacts.captureConfidence })
      .from(contacts)
      .where(eq(contacts.id, contactId));
    captureConfidence = existing?.captureConfidence ?? null;
  }
```

After the `applySignatureToContact` call, arm the flag:

```ts
  // Arm the AI-enhancement flag whenever real body text arrived — including
  // re-arming an 'enhanced' contact (new material to process). Failures
  // downstream never touch this; only a successful apply clears it.
  if (payload.bodyText) {
    await db
      .update(contacts)
      .set({ aiEnhancementStatus: 'pending', aiEnhancementUpdatedAt: now(), updatedAt: now() })
      .where(eq(contacts.id, contactId));
  }
```

Return the extended outcome object with all new fields.

- [ ] **Step 3: Add the emitters**

In `eldrin-crm/worker/services/event-emitter.ts`, following the file's existing pattern:

```ts
export interface CompanyCreatedPayload extends Record<string, unknown> {
  companyId: string;
  domain: string | null;
  isAutoCreated: boolean;
}
export interface EmailExtractionRequestedPayload extends Record<string, unknown> {
  messageId: string;
  contactId: string;
  from: string;
  bodyText: string;
}

export const emitCompanyCreated = (env: Env, payload: CompanyCreatedPayload) =>
  emit(env, 'company.created', payload);
export const emitEmailExtractionRequested = (
  env: Env,
  payload: EmailExtractionRequestedPayload,
) => emit(env, 'email.extraction.requested', payload);
```

- [ ] **Step 4: Emit from the webhook + manual company creation**

In `eldrin-crm/worker/routes/events.ts`, in the `case 'email.received':` block (line ~121), after `const capture = await captureInboundSender(db, payload);` add:

```ts
        if (capture.companyAutoCreated && capture.autoCreatedCompanyId && capture.companyDomain) {
          c.executionCtx.waitUntil(
            emitCompanyCreated(c.env, {
              companyId: capture.autoCreatedCompanyId,
              domain: capture.companyDomain,
              isAutoCreated: true,
            }),
          );
        }
        const lowConfidence =
          capture.captureConfidence !== null && capture.captureConfidence < 0.7;
        if (payload.bodyText && capture.contactId && (capture.contactAutoCreated || lowConfidence)) {
          c.executionCtx.waitUntil(
            emitEmailExtractionRequested(c.env, {
              messageId: payload.messageId,
              contactId: capture.contactId,
              from: payload.from,
              bodyText: payload.bodyText,
            }),
          );
        }
```

(Import both emitters; `payload.messageId` exists on `InboundEmailPayload` — verify the field name at `email-linking.ts:36-49`.)

In `eldrin-crm/worker/routes/companies.ts`:
- `POST /api/companies` handler: after the insert + before returning, add `c.executionCtx.waitUntil(emitCompanyCreated(c.env, { companyId: id, domain: (body.domain?.toLowerCase().trim() || null), isAutoCreated: false }));` (match the handler's actual local variable names).
- `PATCH /api/companies/:id` (line ~322): add the Confirm-action guard alongside the other field guards:

```ts
  // Confirming an auto-captured company clears the review flag; confidence
  // and capture source are kept for provenance (mirrors contacts).
  if (body.isAutoCreated !== undefined) updates.isAutoCreated = Boolean(body.isAutoCreated);
```

and add `isAutoCreated?: boolean;` to the PATCH body type.

- [ ] **Step 5: Declare the events in the manifest**

In `eldrin-crm/public/eldrin-app.manifest.json` `events.emits` array, append:

```json
    { "type": "company.created", "description": "A CRM company was created (isAutoCreated=true for provisional companies captured from email domains)",
      "payload": { "companyId": "string", "domain": "string?", "isAutoCreated": "boolean" } },
    { "type": "email.extraction.requested", "description": "The CRM requests AI insight extraction for a captured email (unknown sender or low-confidence capture)",
      "payload": { "messageId": "string", "contactId": "string", "from": "string", "bodyText": "string" } }
```

- [ ] **Step 6: Run tests + typecheck + commit**

Run: `cd eldrin-crm && npx vitest run && npx tsc -b` — Expected: all pass (existing capture tests must still pass: the outcome object grew but kept its old fields).

```bash
git -C eldrin-crm add worker/services/auto-capture.ts worker/services/event-emitter.ts worker/routes/events.ts worker/routes/companies.ts public/eldrin-app.manifest.json worker/__tests__
git -C eldrin-crm commit -m "feat(capture): provisional companies, AI-enhancement flag arming, company.created + email.extraction.requested events"
```

---

### Task 12: eldrin-crm — enhancement routes (apply ×2, pending, material)

**Files:**
- Create: `eldrin-crm/worker/routes/enhancement.ts`
- Modify: `eldrin-crm/worker/index.ts` (mount), `eldrin-crm/worker/routes/contacts.ts` (material route), `eldrin-crm/public/eldrin-app.manifest.json` (publicRoutes + routes)
- Test: `eldrin-crm/worker/__tests__/enhancement-routes.test.ts`

**Interfaces:**
- Produces (all under the service-secret-gated `/api/enhancement/*` public-route prefix; secret = `X-Eldrin-App-Secret` matching `env.JWT_SECRET`, open when unset — identical semantics to the events webhook):
  - `POST /api/enhancement/companies/:id` body `{data: {name?, description?, logoUrl?, industry?}, source?}` → 200 `{company, applied: string[]}`. Fill-empty-only (name applies only when current name is empty or equals the domain placeholder; description → `notes`; logoUrl must be http(s)). Flag → `enhanced`; if `isAutoCreated` and anything applied, `captureConfidence = min(0.95, (current ?? 0.3) + 0.1)`.
  - `POST /api/enhancement/contacts/:id` body `{messageId: string, insights: {jobTitle?, phones?, social?, companyName?, address?}, source?}` → 200 `{contact, applied: string[]}`. Applies jobTitle/phones/social via `applySignatureToContact` (fill-empty + phone dedup already implemented there); `companyName`/`address` accepted, ignored (deviation 4). Flag → `enhanced`; same confidence bump.
  - `GET /api/enhancement/pending?type=contact|company&limit=&offset=` → 200 `{items: [...], limit, offset}` where contact items are `{type:'contact', id, firstName, lastName, from, bodyText, messageId}` (material from the latest email activity's metadata) and company items are `{type:'company', id, name, domain}`.
  - `GET /api/contacts/:id/enhancement-material` (normal JWT route, permission `contacts:read`) → 200 `{messageId, from, bodyText}` or 404 when the contact has no email activity with bodyText. Used by the frontend Enhance-now button.

- [ ] **Step 1: Write failing tests**

Create `eldrin-crm/worker/__tests__/enhancement-routes.test.ts`:

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { Hono } from 'hono';
import { eq } from 'drizzle-orm';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import { companies, contacts, activities } from '../db';
import { enhancementRoutes } from '../routes/enhancement';

const T0 = 1700000000000;
const SECRET = 'test-service-secret';
const mockEnvBindings = { JWT_SECRET: SECRET } as Env;

function createApp(db: Database) {
  const app = new Hono<{ Bindings: Env; Variables: { db: Database } }>();
  app.use('*', async (c, next) => {
    c.set('db', db);
    await next();
  });
  app.route('', enhancementRoutes);
  return app;
}

function post(app: ReturnType<typeof createApp>, path: string, body: unknown, secret = SECRET) {
  return app.request(
    path,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Eldrin-App-Secret': secret },
      body: JSON.stringify(body),
    },
    mockEnvBindings,
  );
}

async function seedCompany(db: Database, overrides: Partial<typeof companies.$inferInsert> = {}) {
  await db.insert(companies).values({
    id: 'co1',
    name: 'newcorp.com',
    domain: 'newcorp.com',
    isAutoCreated: true,
    captureConfidence: 0.3,
    aiEnhancementStatus: 'pending',
    createdBy: 'system',
    createdAt: T0,
    updatedAt: T0,
    ...overrides,
  });
}

describe('POST /api/enhancement/companies/:id', () => {
  let db: Database;
  let app: ReturnType<typeof createApp>;

  beforeEach(() => {
    db = createTestDb();
    app = createApp(db);
  });

  it('rejects a wrong service secret', async () => {
    await seedCompany(db);
    const res = await post(app, '/api/enhancement/companies/co1', { data: {} }, 'wrong');
    expect(res.status).toBe(401);
  });

  it('applies fill-empty-only and flips the flag to enhanced', async () => {
    await seedCompany(db);
    const res = await post(app, '/api/enhancement/companies/co1', {
      data: { name: 'NewCorp Inc', description: 'Anvil makers', logoUrl: 'https://x.com/l.png' },
      source: 'workflow:enrich-company',
    });
    expect(res.status).toBe(200);
    const { applied } = (await res.json()) as { applied: string[] };
    expect(applied).toEqual(expect.arrayContaining(['name', 'notes', 'logoUrl']));

    const [row] = await db.select().from(companies).where(eq(companies.id, 'co1'));
    expect(row.name).toBe('NewCorp Inc');       // placeholder name === domain → fillable
    expect(row.notes).toBe('Anvil makers');     // description maps to notes
    expect(row.aiEnhancementStatus).toBe('enhanced');
    expect(row.captureConfidence).toBeCloseTo(0.4); // 0.3 + 0.1 bump
  });

  it('never overwrites populated fields (idempotent re-apply)', async () => {
    await seedCompany(db, { name: 'Real Name', notes: 'existing notes' });
    const res = await post(app, '/api/enhancement/companies/co1', {
      data: { name: 'Scraped Name', description: 'scraped' },
    });
    const { applied } = (await res.json()) as { applied: string[] };
    expect(applied).toEqual([]);
    const [row] = await db.select().from(companies).where(eq(companies.id, 'co1'));
    expect(row.name).toBe('Real Name');
    expect(row.notes).toBe('existing notes');
    expect(row.aiEnhancementStatus).toBe('enhanced'); // processed, even if nothing applied
  });

  it('rejects non-http(s) logo URLs and oversized fields', async () => {
    await seedCompany(db);
    const res = await post(app, '/api/enhancement/companies/co1', {
      data: { logoUrl: 'javascript:alert(1)', name: 'x'.repeat(300) },
    });
    expect(res.status).toBe(200); // invalid fields are dropped, not fatal
    const [row] = await db.select().from(companies).where(eq(companies.id, 'co1'));
    expect(row.logoUrl).toBeNull();
    expect(row.name).toBe('newcorp.com');
  });

  it('404s for unknown companies', async () => {
    const res = await post(app, '/api/enhancement/companies/nope', { data: {} });
    expect(res.status).toBe(404);
  });
});

describe('POST /api/enhancement/contacts/:id', () => {
  let db: Database;
  let app: ReturnType<typeof createApp>;

  beforeEach(async () => {
    db = createTestDb();
    app = createApp(db);
    await db.insert(contacts).values({
      id: 'c1',
      firstName: 'Jane',
      lastName: 'Doe',
      aiEnhancementStatus: 'pending',
      isAutoCreated: true,
      captureConfidence: 0.7,
      createdBy: 'system',
      createdAt: T0,
      updatedAt: T0,
    });
  });

  it('applies insights fill-empty-only and flips the flag', async () => {
    const res = await post(app, '/api/enhancement/contacts/c1', {
      messageId: 'm1',
      insights: { jobTitle: 'CTO', phones: ['+1 555 010 1234'], social: { linkedin: 'https://linkedin.com/in/jane' } },
    });
    expect(res.status).toBe(200);
    const [row] = await db.select().from(contacts).where(eq(contacts.id, 'c1'));
    expect(row.jobTitle).toBe('CTO');
    expect(row.aiEnhancementStatus).toBe('enhanced');
  });

  it('requires messageId', async () => {
    const res = await post(app, '/api/enhancement/contacts/c1', { insights: {} });
    expect(res.status).toBe(400);
  });
});

describe('GET /api/enhancement/pending', () => {
  it('lists pending records with their material', async () => {
    const db = createTestDb();
    const app = createApp(db);
    await seedCompany(db);
    await db.insert(contacts).values({
      id: 'c1', firstName: 'Jane', lastName: 'Doe',
      aiEnhancementStatus: 'pending', createdBy: 'system', createdAt: T0, updatedAt: T0,
    });
    await db.insert(activities).values({
      id: 'a1',
      typeId: 'email',
      title: 'Hello',
      status: 'completed',
      priority: 'medium',
      relatedRecordId: 'c1',
      relatedRecordType: 'contact',
      completedAt: T0,
      sourceMessageId: 'm1',
      metadata: JSON.stringify({ direction: 'inbound', from: 'jane@newcorp.com', to: [], bodyText: 'the body' }),
      createdBy: 'system',
      createdAt: T0,
      updatedAt: T0,
    });

    const res = await app.request(
      '/api/enhancement/pending',
      { headers: { 'X-Eldrin-App-Secret': SECRET } },
      mockEnvBindings,
    );
    expect(res.status).toBe(200);
    const { items } = (await res.json()) as { items: Array<Record<string, unknown>> };
    const contact = items.find((i) => i.type === 'contact');
    const company = items.find((i) => i.type === 'company');
    expect(contact).toMatchObject({ id: 'c1', bodyText: 'the body', messageId: 'm1', from: 'jane@newcorp.com' });
    expect(company).toMatchObject({ id: 'co1', domain: 'newcorp.com' });
  });
});
```

Note: the `activities` insert must satisfy that table's NOT NULL columns — open `schema.ts`'s `activities` definition and the `EMAIL_ACTIVITY_TYPE_ID` constant in `email-linking.ts`; use the real `typeId` value and add any other required columns.

Run: `cd eldrin-crm && npx vitest run worker/__tests__/enhancement-routes.test.ts` — Expected: FAIL (module missing).

- [ ] **Step 2: Implement `worker/routes/enhancement.ts`**

```ts
import { Hono } from 'hono';
import { and, desc, eq } from 'drizzle-orm';
import type { Database } from '../db';
import { activities, companies, contacts } from '../db';
import { applySignatureToContact } from '../services/signature-parser';
import { now } from '../utils';

/**
 * Service-facing AI-enhancement endpoints. Reached through core's app proxy
 * by workflow call_app_api steps and (later) a local enhancer app. Public in
 * the manifest ("/enhancement/*"); each handler enforces the shared service
 * secret — the exact pattern of the events webhook.
 */
export const enhancementRoutes = new Hono<{ Bindings: Env; Variables: { db: Database } }>();

function isValidServiceSecret(
  configuredSecret: string | undefined,
  header: string | undefined,
): boolean {
  if (!configuredSecret) return true;
  return header === configuredSecret;
}

function unauthorized(c: Parameters<Parameters<typeof enhancementRoutes.post>[1]>[0]) {
  return c.json({ error: 'Invalid service secret' }, 401);
}

const MAX_LENGTHS = { name: 200, description: 2000, logoUrl: 500, industry: 100 } as const;

function cleanString(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > max) return null;
  return trimmed;
}

function bumpedConfidence(current: number | null): number {
  return Math.min(0.95, Math.round(((current ?? 0.3) + 0.1) * 100) / 100);
}

// ── POST /api/enhancement/companies/:id ─────────────────────────────────────
enhancementRoutes.post('/api/enhancement/companies/:id', async (c) => {
  if (!isValidServiceSecret(c.env.JWT_SECRET, c.req.header('X-Eldrin-App-Secret'))) {
    return unauthorized(c);
  }
  const db = c.get('db');
  const id = c.req.param('id');

  const [existing] = await db
    .select()
    .from(companies)
    .where(and(eq(companies.id, id), eq(companies.isDeleted, false)));
  if (!existing) return c.json({ error: 'Company not found' }, 404);

  let body: { data?: Record<string, unknown>; source?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  const data = body.data ?? {};

  const applied: string[] = [];
  const updates: Record<string, unknown> = {};

  const name = cleanString(data.name, MAX_LENGTHS.name);
  const namePlaceholder = existing.name.trim() === '' || existing.name === existing.domain;
  if (name && namePlaceholder && name !== existing.name) {
    updates.name = name;
    applied.push('name');
  }
  const description = cleanString(data.description, MAX_LENGTHS.description);
  if (description && !existing.notes) {
    updates.notes = description; // companies has no description column
    applied.push('notes');
  }
  const logoUrl = cleanString(data.logoUrl, MAX_LENGTHS.logoUrl);
  if (logoUrl && /^https?:\/\//i.test(logoUrl) && !existing.logoUrl) {
    updates.logoUrl = logoUrl;
    applied.push('logoUrl');
  }
  const industry = cleanString(data.industry, MAX_LENGTHS.industry);
  if (industry && !existing.industry) {
    updates.industry = industry;
    applied.push('industry');
  }

  if (existing.isAutoCreated && applied.length > 0) {
    updates.captureConfidence = bumpedConfidence(existing.captureConfidence);
  }
  updates.aiEnhancementStatus = 'enhanced';
  updates.aiEnhancementUpdatedAt = now();
  updates.updatedAt = now();

  await db.update(companies).set(updates).where(eq(companies.id, id));
  const [company] = await db.select().from(companies).where(eq(companies.id, id));
  return c.json({ company, applied });
});

// ── POST /api/enhancement/contacts/:id ──────────────────────────────────────
enhancementRoutes.post('/api/enhancement/contacts/:id', async (c) => {
  if (!isValidServiceSecret(c.env.JWT_SECRET, c.req.header('X-Eldrin-App-Secret'))) {
    return unauthorized(c);
  }
  const db = c.get('db');
  const id = c.req.param('id');

  const [existing] = await db
    .select()
    .from(contacts)
    .where(and(eq(contacts.id, id), eq(contacts.isDeleted, false)));
  if (!existing) return c.json({ error: 'Contact not found' }, 404);

  let body: { messageId?: string; insights?: Record<string, unknown>; source?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  if (typeof body.messageId !== 'string' || !body.messageId.trim()) {
    return c.json({ error: 'messageId is required' }, 400);
  }
  const insights = body.insights ?? {};

  // Map to the signature-parser's ParsedSignature shape and reuse its
  // fill-empty + phone-dedup apply. companyName/address: accepted, ignored
  // this slice. NOTE: confirm the exported ParsedSignature field names in
  // services/signature-parser.ts and adjust this mapping if they differ.
  const parsed = {
    jobTitle: typeof insights.jobTitle === 'string' ? insights.jobTitle.trim() || null : null,
    phones: Array.isArray(insights.phones)
      ? insights.phones.filter((p): p is string => typeof p === 'string' && p.trim().length > 0)
      : [],
    social:
      typeof insights.social === 'object' && insights.social !== null
        ? (insights.social as Record<string, string>)
        : {},
  };
  const { updated } = await applySignatureToContact(db, id, parsed);
  const applied = updated ? ['signature-fields'] : [];

  const updates: Record<string, unknown> = {
    aiEnhancementStatus: 'enhanced',
    aiEnhancementUpdatedAt: now(),
    updatedAt: now(),
  };
  if (existing.isAutoCreated && updated) {
    updates.captureConfidence = bumpedConfidence(existing.captureConfidence);
  }
  await db.update(contacts).set(updates).where(eq(contacts.id, id));

  const [contact] = await db.select().from(contacts).where(eq(contacts.id, id));
  return c.json({ contact, applied });
});

// ── GET /api/enhancement/pending ─────────────────────────────────────────────
enhancementRoutes.get('/api/enhancement/pending', async (c) => {
  if (!isValidServiceSecret(c.env.JWT_SECRET, c.req.header('X-Eldrin-App-Secret'))) {
    return unauthorized(c);
  }
  const db = c.get('db');
  const type = c.req.query('type'); // contact | company | undefined (both)
  const limit = Math.min(Number(c.req.query('limit')) || 25, 100);
  const offset = Number(c.req.query('offset')) || 0;

  const items: Array<Record<string, unknown>> = [];

  if (type !== 'company') {
    const pendingContacts = await db
      .select()
      .from(contacts)
      .where(and(eq(contacts.aiEnhancementStatus, 'pending'), eq(contacts.isDeleted, false)))
      .limit(limit)
      .offset(offset);
    for (const contact of pendingContacts) {
      const material = await latestEmailMaterial(db, contact.id);
      items.push({
        type: 'contact',
        id: contact.id,
        firstName: contact.firstName,
        lastName: contact.lastName,
        ...(material ?? {}),
      });
    }
  }
  if (type !== 'contact') {
    const pendingCompanies = await db
      .select({ id: companies.id, name: companies.name, domain: companies.domain })
      .from(companies)
      .where(and(eq(companies.aiEnhancementStatus, 'pending'), eq(companies.isDeleted, false)))
      .limit(limit)
      .offset(offset);
    for (const company of pendingCompanies) {
      items.push({ type: 'company', ...company });
    }
  }

  return c.json({ items, limit, offset });
});

/** Latest email activity's bodyText/from/messageId for a contact, if any. */
export async function latestEmailMaterial(
  db: Database,
  contactId: string,
): Promise<{ messageId: string; from: string; bodyText: string } | null> {
  const rows = await db
    .select({ metadata: activities.metadata, sourceMessageId: activities.sourceMessageId })
    .from(activities)
    .where(
      and(
        eq(activities.relatedRecordId, contactId),
        eq(activities.relatedRecordType, 'contact'),
      ),
    )
    .orderBy(desc(activities.completedAt))
    .limit(5);
  for (const row of rows) {
    if (!row.metadata || !row.sourceMessageId) continue;
    try {
      const metadata = JSON.parse(row.metadata) as { from?: string; bodyText?: string };
      if (metadata.bodyText) {
        return { messageId: row.sourceMessageId, from: metadata.from ?? '', bodyText: metadata.bodyText };
      }
    } catch {
      continue;
    }
  }
  return null;
}
```

Adjust the `now` import to wherever the other route files get it (check `contacts.ts` imports — likely `../utils`). If `applySignatureToContact` lives in `auto-capture.ts` rather than `signature-parser.ts`, fix the import (check both files' exports).

- [ ] **Step 3: Material route + mounting + manifest**

In `eldrin-crm/worker/routes/contacts.ts`, add (BEFORE `GET /api/contacts/:id` so `enhancement-material` isn't swallowed — check the file's route order; Hono matches in registration order):

```ts
// Material for the frontend "Enhance now" button: the latest captured email
// body for this contact. Normal JWT route (contacts:read).
contactRoutes.get('/api/contacts/:id/enhancement-material', async (c) => {
  const db = c.get('db');
  const id = c.req.param('id');
  const { latestEmailMaterial } = await import('./enhancement');
  const material = await latestEmailMaterial(db, id);
  if (!material) return c.json({ error: 'No email material available' }, 404);
  return c.json(material);
});
```

In `eldrin-crm/worker/index.ts`: `import { enhancementRoutes } from './routes/enhancement';` and `app.route('', enhancementRoutes);` alongside the other mounts.

In `eldrin-crm/public/eldrin-app.manifest.json`:
- `api.publicRoutes`: append `"/enhancement/*"`.
- `api.routes`: append `{ "method": "GET", "path": "/api/contacts/:id/enhancement-material", "permission": "contacts:read" }`.

- [ ] **Step 4: Run tests + typecheck + commit**

Run: `cd eldrin-crm && npx vitest run && npx tsc -b` — Expected: all pass.

```bash
git -C eldrin-crm add worker/routes/enhancement.ts worker/routes/contacts.ts worker/index.ts public/eldrin-app.manifest.json worker/__tests__/enhancement-routes.test.ts
git -C eldrin-crm commit -m "feat(api): AI-enhancement apply/pending/material endpoints (service-secret gated)"
```

---

### Task 13: eldrin-crm — frontend (badge, Enhance-now, useWorkflowsApp, company Confirm)

The CRM has no frontend test suite; the gate for this task is `npx tsc -b` + `npm run build` green, with live verification in Task 14.

**Files:**
- Create: `eldrin-crm/src/hooks/useWorkflowsApp.ts`, `eldrin-crm/src/components/shared/AiEnhancementBadge.tsx`
- Modify: `eldrin-crm/src/api.ts`, `eldrin-crm/src/pages/contacts/ContactDetail.tsx`, `eldrin-crm/src/pages/companies/CompanyDetail.tsx`

**Interfaces:**
- Consumes: `GET /api/contacts/:id/enhancement-material` (Task 12); eldrin-workflows routes through the shell proxy: `GET /api/app/eldrin-workflows/api/workflows`, `POST /api/app/eldrin-workflows/api/workflows/:id/run` (both pre-existing in eldrin-workflows).
- Produces: `useWorkflowsApp(): {isAvailable, loading, findWorkflowByName(name), runWorkflow(id, payload)}`; `<AiEnhancementBadge />`; Enhance-now buttons on both detail pages; auto-captured badge + Confirm on CompanyDetail.

- [ ] **Step 1: `useWorkflowsApp` hook**

Create `eldrin-crm/src/hooks/useWorkflowsApp.ts`, cloning the structure of `src/hooks/useEmailApp.ts` (Zustand availability store + `claimCheck()` one-shot detection via `GET /api/apps` + `useAuthHeaders()` in a ref). Replace the email-specific parts:

```ts
const WORKFLOWS_APP_ID = 'eldrin-workflows';
const WORKFLOWS_API_BASE = `/api/app/${WORKFLOWS_APP_ID}/api`;
```

API methods (same `request`-style helper as useEmailApp's `emailAppRequest`):

```ts
export interface WorkflowSummary {
  id: string;
  name: string;
  isActive: boolean;
}

// inside the hook:
const findWorkflowByName = useCallback(async (name: string): Promise<WorkflowSummary | null> => {
  const data = await workflowsAppRequest<{ workflows?: WorkflowSummary[] }>(
    headersRef.current,
    '/workflows',
  );
  const list = Array.isArray(data.workflows) ? data.workflows : [];
  return list.find((w) => w.name === name) ?? null;
}, []);

const runWorkflow = useCallback(
  async (workflowId: string, payload: Record<string, unknown>): Promise<void> => {
    await workflowsAppRequest(headersRef.current, `/workflows/${workflowId}/run`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },
  [],
);
```

Return `{ isAvailable, loading, findWorkflowByName, runWorkflow }`. Copy useEmailApp's availability detection verbatim, changing only the app id it looks for (the detector matches core's snake_case `app_id` — keep that). If `GET /api/workflows` responds with a different envelope than `{workflows: [...]}`, normalize like useEmailApp's `extractList` does.

- [ ] **Step 2: Badge component**

Create `eldrin-crm/src/components/shared/AiEnhancementBadge.tsx`:

```tsx
import { Wand2 } from 'lucide-react';

interface AiEnhancementBadgeProps {
  size?: 'xs' | 'sm';
}

/** Shown while a record's ai_enhancement_status is 'pending'. */
export function AiEnhancementBadge({ size = 'xs' }: AiEnhancementBadgeProps) {
  const sizeClass = size === 'sm' ? 'badge-sm' : 'badge-xs';
  return (
    <span className="tooltip" data-tip="Awaiting AI enhancement — new email material has not been processed yet">
      <span className={`badge ${sizeClass} badge-info badge-outline gap-1`}>
        <Wand2 className="w-3 h-3" /> AI pending
      </span>
    </span>
  );
}
```

- [ ] **Step 3: api.ts additions**

In `eldrin-crm/src/api.ts`, following the `(base, headers, …)` convention of the surrounding functions:

```ts
export interface EnhancementMaterial {
  messageId: string;
  from: string;
  bodyText: string;
}

export async function getEnhancementMaterial(
  base: string,
  headers: Headers,
  contactId: string,
): Promise<EnhancementMaterial> {
  return request(apiUrl(base, `/contacts/${contactId}/enhancement-material`), headers);
}
```

Also extend the exported `Contact` and `Company` types (wherever they're declared in this file) with `aiEnhancementStatus?: string | null;` and, on `Company`, `isAutoCreated?: boolean; captureConfidence?: number | null;`.

- [ ] **Step 4: ContactDetail wiring**

In `eldrin-crm/src/pages/contacts/ContactDetail.tsx`:
- Import `AiEnhancementBadge`, `useWorkflowsApp`, `getEnhancementMaterial` (via the file's `api` import style).
- Next to the existing `AutoCapturedBadge` render (line ~205): `{contact.aiEnhancementStatus === 'pending' && <AiEnhancementBadge size="sm" />}`
- Next to the Confirm button (line ~224), add Enhance-now (visible when pending AND workflows app available):

```tsx
{contact.aiEnhancementStatus === 'pending' && workflowsApp.isAvailable && (
  <button
    className="btn btn-info btn-sm btn-outline gap-1"
    onClick={handleEnhanceNow}
    disabled={enhancing}
    title="Run AI enhancement for this contact now"
  >
    <Wand2 className="w-4 h-4" /> {enhancing ? 'Requested…' : 'Enhance now'}
  </button>
)}
```

Handler (mirror the file's existing async-handler + toast/error conventions — reuse whatever notification helper `handleConfirmAutoCreated` uses):

```tsx
const workflowsApp = useWorkflowsApp();
const [enhancing, setEnhancing] = useState(false);

async function handleEnhanceNow() {
  if (!contact) return;
  setEnhancing(true);
  try {
    const material = await api.getEnhancementMaterial(apiBase, authHeaders, contact.id);
    const workflow = await workflowsApp.findWorkflowByName('CRM: Extract email insights');
    if (!workflow) throw new Error('Enhancement workflow is not installed');
    // Same payload shape the event trigger carries — one definition, both paths.
    await workflowsApp.runWorkflow(workflow.id, {
      messageId: material.messageId,
      contactId: contact.id,
      from: material.from,
      bodyText: material.bodyText,
    });
  } catch (err) {
    console.error('Enhance now failed:', err);
  } finally {
    setEnhancing(false);
  }
}
```

(Replace the `console.error` with the page's existing error-toast mechanism if one exists — check how other handlers surface errors in this file.)

- [ ] **Step 5: CompanyDetail wiring**

In `eldrin-crm/src/pages/companies/CompanyDetail.tsx` (which currently has NO capture UI):
- Render `AutoCapturedBadge` (import from `../../components/contacts/AutoCapturedBadge`) + `AiEnhancementBadge` in the header when `company.isAutoCreated` / `company.aiEnhancementStatus === 'pending'` — same placement pattern as ContactDetail.
- Add a Confirm button calling the page's existing company-update api function with `{ isAutoCreated: false }` (find the `updateCompany`-style function in `api.ts` — same call shape as ContactDetail's `handleConfirmAutoCreated`).
- Add Enhance-now (workflow `'CRM: Enrich new company'`, payload `{ companyId: company.id, domain: company.domain, isAutoCreated: true }`) with the same `useWorkflowsApp` + `enhancing` state pattern as Step 4.

- [ ] **Step 6: Typecheck, build, commit**

Run: `cd eldrin-crm && npx tsc -b && npm run build`
Expected: clean.

```bash
git -C eldrin-crm add src/hooks/useWorkflowsApp.ts src/components/shared/AiEnhancementBadge.tsx src/api.ts src/pages/contacts/ContactDetail.tsx src/pages/companies/CompanyDetail.tsx
git -C eldrin-crm commit -m "feat(ui): AI-pending badge, Enhance-now via eldrin-workflows, company Confirm"
```

---

### Task 14: live validation, docs, merges

The cross-repo seam is where past slices found their real bugs (proxy double-`/api`, stale SDK dist, missing CORS) — unit suites do not prove it. Chrome-devtools verification is the gate for DONE.

**Files:**
- Modify: `docs/eldrin-crm-implementation/01_core_crm_foundation_mvp/phases/phase-10-zero-data-entry/STATUS.md`, `docs/eldrin-crm-implementation/NEXT_STEPS.md` (parent repo)
- Create: `eldrin-workflows/.dev.vars` (local only, NOT committed)

**Interfaces:** none — this task is verification + documentation.

- [ ] **Step 1: Local env wiring**

Create `eldrin-workflows/.dev.vars` (gitignored — verify with `git -C eldrin-workflows status --short` afterwards) containing the shared dev `JWT_SECRET` (copy the value from `eldrin-crm/.dev.vars`) plus `CORE_URL=http://localhost:4000` and `AI_PROVIDER=mock`.

- [ ] **Step 2: Start the stack**

Four dev servers (each `npm run dev` in its repo): eldrin-core (:4000), eldrin-email (:4010), eldrin-crm (:4009), eldrin-workflows (:4008). Confirm eldrin-workflows is registered + enabled in core's `platform_apps` (it was live-validated on the bus 2026-07-02; if missing, register it the same way the email app was).

- [ ] **Step 3: Import + activate the workflow templates**

```bash
cd eldrin-workflows
curl -s -X POST http://localhost:4008/api/workflows/import \
  -H 'Content-Type: application/json' \
  -d "{\"workflows\": [$(cat workflows-templates/crm-enrich-company.json), $(cat workflows-templates/crm-extract-email-insights.json)]}"
```

Expected: both `"status": "created"`. Re-run the same command — both `"status": "skipped"` (idempotency proven live). Activate each: `curl -X POST http://localhost:4008/api/workflows/<id>/activate` (ids from the import response).

- [ ] **Step 4: Live scenarios (chrome-devtools verified)**

Work through these in order; every item must pass before DONE:

1. **Happy path:** send a real email from an address on an unknown corporate domain to the connected mailbox → CRM auto-creates the contact AND a provisional company (name = domain, badges visible in the shell UI) → both workflows fire (check run history at :4008) → company gets real name/notes/logo from its homepage; contact gets mock-extracted jobTitle/phones/social → both flags `enhanced`, "AI pending" badges gone after reload.
2. **Freemail guard:** send from a gmail.com address → contact captured, NO company created.
3. **Failure durability:** set `AI_PROVIDER=openai` with `AI_OPENAI_BASE_URL=http://localhost:9` (dead port) in `.dev.vars`, restart :4008, send another email → extraction run FAILS in run history → contact flag stays `pending` → record appears in `GET /api/enhancement/pending` (curl with the secret header). Restore `AI_PROVIDER=mock`.
4. **Manual path:** on the still-pending contact, click **Enhance now** → run appears (triggerType `manual`), insights applied, flag `enhanced`.
5. **Auth:** curl `POST /api/enhancement/contacts/<id>` directly on :4009 with a wrong secret → 401; curl the core proxy `POST :4000/api/app/eldrin-crm/api/enhancement/pending` with a wrong secret → 401, with the right secret → 200.
6. **Company Confirm:** CompanyDetail Confirm button clears the auto-created badge.
7. **Regression:** `npx vitest run` green in eldrin-workflows, eldrin-crm, and eldrin-core; `npx tsc -b` + `npm run build` green in all three.

Fix anything found (the SP8 lesson: live testing finds what suites don't), committing fixes to the owning repo.

- [ ] **Step 5: Documentation + merges**

1. Update `phase-10-zero-data-entry/STATUS.md`: mark Slice 3 (enrichment via workflows + AI extraction + pending-flag/pull contract) done with a dated note listing what shipped and what remains (ghost detection → next mini-slice; local enhancer app → future; calendar → slice 4).
2. Update `NEXT_STEPS.md` step 2: check off Slice 3 with the same summary; note in step 3 that `call_app_api` shipped.
3. Merge per repo (use the superpowers:finishing-a-development-branch skill): eldrin-workflows `feature/ai-enhancement` → main; eldrin-core `feature/service-principal-proxy` → main; eldrin-crm stays on `feature/phase-07-email-integration` unless the user wants it merged — ask.
4. Parent repo: commit doc updates + submodule pointer bumps (one commit, per convention), push.

---

## Self-Review Notes (already applied)

- **Spec coverage:** D1-D9 all mapped: no-new-extension (whole plan), split ghost/deal (out of scope), free metadata provider (T3), hybrid (T13 manual + T11 events), core-proxy routing (T6+T8), three providers (T4+T5), CRM-orchestrated extraction (T11), flag lifecycle + pull contract (T9+T11+T12), JSON templates + import (T7). bodyText persistence (T10), SSRF guard (T11 `isEnrichableDomain`), manifest updates (T11+T12), testing per spec (each task), live-validation gate (T14).
- **Type consistency check:** `InboundCaptureOutcome` fields in T11 match T11's tests and T12's non-usage; `latestEmailMaterial` produced in T12 and consumed by the material route in T12; step configs in T7 templates match the runners' config contracts in T3/T4/T6; `applied`/`{company}` envelopes consistent between T12 impl and tests.
- **Known verify-on-site points (flagged inline, not placeholders):** exact `ParsedSignature` field names (T12), `GET /api/workflows` list envelope (T7/T13), activities NOT-NULL columns for the seed (T12), `equals` operator spelling (T7). Each has an explicit instruction for what to check and where.


