# Eldrin Email Client — How To Work On This

## Documents

| File | Purpose |
|------|---------|
| `eldrin-email-requirements.md` | Full requirements (46 items across 7 categories) |
| `eldrin-email-plan.md` | Master plan: architecture, events, manifest, design decisions |
| `phases/phase-NN-*/PLAN.md` | Detailed implementation steps per phase |
| `phases/phase-NN-*/STATUS.md` | Progress tracking per phase |
| `phases/phase-NN-*/DONE.md` | Created when a phase is complete |

## Finding the Next Task

```bash
# Check all phase statuses
grep -r "^## Status:" docs/eldrin_email_client/phases/*/STATUS.md

# Find the first not_started phase
grep -r "not_started" docs/eldrin_email_client/phases/*/STATUS.md | head -1
```

## Implementation Order

```
Phase 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → (10)
```

1. **Project Scaffolding** — repo setup, boilerplate
2. **Mailbox Connection (Gmail)** — OAuth, token encryption, settings UI
3. **Email Sync Engine** — background sync, dedup, storage
4. **Inbox & Thread UI** — inbox list, thread view, search
5. **Email Composition & Sending** — TipTap composer, send via Gmail API
6. **Email Templates** — template CRUD, merge fields, preview
7. **Email Tracking** — open pixel, click wrapping, tracking events
8. **Cross-App Integration API** — send API, event emission, webhook handler
9. **Outlook / Microsoft 365** — Microsoft Graph OAuth, provider abstraction
10. **IMAP/SMTP Support** — optional, for self-hosted mail

## Working on a Phase

1. Read the phase's `PLAN.md` for detailed steps
2. Update `STATUS.md` as you complete each step
3. When all steps pass the test gate, create `DONE.md`
4. Move to the next phase

## Repository Setup

The `eldrin-email` app will be a new Git submodule:

```bash
# From the parent eldrin/ directory
cd /Users/tibor/projects/eldrin
# Create the repo (or clone if it already exists on GitHub)
git submodule add <repo-url> eldrin-email
cd eldrin-email
npm install
```

## Development

```bash
cd eldrin-email
npm run dev              # Vite dev server (frontend + worker)
npm run dev:worker       # Wrangler dev (worker only)
npm run build            # Production build
npm run test             # Run tests
```

## Local Database

```bash
# Run migrations on local D1
npx wrangler d1 execute eldrin-email-db --local --file=migrations/001-mailboxes.sql
```

## Testing Cross-App Events

With both `eldrin-email` and `eldrin-crm` running locally:

1. Send an email from `eldrin-email` → emits `email.sent` event
2. Platform delivers to `eldrin-crm` webhook → CRM creates activity on matching contact
3. Check CRM contact timeline for the logged email
