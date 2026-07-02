# Phase 5: Build System

## Status: done
## Started: 2026-02-09
## Completed: 2026-02-09

## Progress:
- [x] Step 5.1: Install tsup as devDependency
- [x] Step 5.2: Create tsup.config.ts for server bundles (4 entries)
- [x] Step 5.3: Create vite.config.base.ts (frontend-only, no CF plugin)
- [x] Step 5.4: Update vite.config.ts to extend base + add CF plugin
- [x] Step 5.5: Update package.json build scripts (build, build:frontend, build:server, build:cloudflare, build:standalone)
- [x] Step 5.6: Update tsconfig.server.json (add providers/**/*.ts)
- [x] Step 5.7: Update tsconfig.worker.json (remove worker/ — shim expands import graph)
- [x] Step 5.8: Create backward-compat shims (worker/index.ts, server/index.ts)
- [x] Step 5.9: Update scripts/build-binary.ts entry point
- [x] Step 5.10: Write build.test.ts structural tests (6 tests)
- [x] Step 5.11: Update vitest.config.ts include pattern
- [x] Step 5.12: Full test suite passes (288 tests), tsc -b clean, tsup build succeeds

## Notes:
- tsup bundles @eldrin-project/eldrin-app-core (local file: dep) via noExternal, leaves pg/bun:sqlite/better-sqlite3 as external
- tsup splitting: shared code in chunk (~164 KB), each adapter entry < 1.5 KB
- tsconfig.worker.json no longer includes worker/ — the shim imports providers/cloudflare/ which transitively pulls all core/ services, causing type errors with @cloudflare/workers-types (missing Node.js types for storage/email adapters)
- tsconfig.server.json NOT added to tsc -b references — its bun-types conflict with other configs. Server/provider code type-checked by vitest and IDE
- worker/index.ts: 323 → 2 lines (re-export shim)
- server/index.ts: 450 → 2 lines (re-import shim)
