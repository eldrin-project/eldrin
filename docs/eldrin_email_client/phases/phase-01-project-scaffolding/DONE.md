# Phase 1: Project Scaffolding — DONE

## Completed: 2026-02-17

## What was built

### Project structure
```
eldrin-email/
├── package.json                    # Dependencies matching eldrin-crm pattern
├── tsconfig.json                   # Root config (references app/node/worker)
├── tsconfig.app.json               # Frontend (React, JSX, DOM)
├── tsconfig.node.json              # Build tooling (Node, scripts)
├── tsconfig.worker.json            # Worker (extends node, CF types)
├── vite.config.ts                  # React + Cloudflare + Tailwind + devShellCompat
├── vitest.config.ts                # Separate test config (no CF plugin)
├── wrangler.jsonc                  # D1 binding (eldrin-email-db)
├── worker-configuration.d.ts       # Env types (DB, ASSETS, JWT_SECRET)
├── index.html                      # Standalone dev entry
├── .gitignore                      # Standard ignores + migrations.generated.ts
├── shims/better-sqlite3.js         # Node.js module shim for bundler
├── scripts/generate-migrations.ts  # SQL → migrations.generated.ts bundler
├── migrations/                     # Empty (tables added in later phases)
├── public/
│   └── eldrin-app.manifest.json    # Full manifest with events, permissions, API routes
├── worker/
│   ├── index.ts                    # Hono app: CORS, health, migrations, event webhook
│   ├── db/
│   │   ├── index.ts                # Drizzle D1 factory
│   │   └── schema.ts              # Empty schema (tables added later)
│   ├── migrations.generated.ts     # Generated (gitignored)
│   └── __tests__/
│       └── health.test.ts          # 4 scaffold tests
└── src/
    ├── eldrin-email.tsx             # single-spa entry (createApp + singleSpaReact)
    ├── main.tsx                     # Standalone dev entry
    ├── root.component.tsx           # Router + theme sync + Sonner toasts
    ├── index.css                    # Tailwind + daisyUI 5 (eldrin/eldrin-dark themes)
    ├── env.d.ts                     # Vite client types
    └── pages/
        ├── inbox/InboxList.tsx      # "No emails yet" placeholder
        ├── sent/SentList.tsx        # Placeholder
        ├── templates/TemplateList.tsx # Placeholder
        └── settings/MailboxSettings.tsx # "Connect your mailbox" placeholder
```

### Manifest highlights
- **Events emitted**: email.received, email.sent, email.opened, email.clicked, email.bounced, email.mailbox.connected/disconnected/error
- **Events subscribed**: email.send.requested, user.deleted, * (catch-all)
- **Public routes**: /health, /api/track/:trackingId/pixel.gif, /api/track/:trackingId/click
- **Permission groups**: Admin (full), User (send/receive/templates), Viewer (read-only)
- **Side nav**: Inbox, Sent, Templates

## Test gate
- `npm run build` — zero TypeScript errors, worker + client bundles produced
- `npm run test` — 4 tests passing (manifest validation)
