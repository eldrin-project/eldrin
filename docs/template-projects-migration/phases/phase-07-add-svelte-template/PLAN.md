# Phase 7: Add Svelte Template to eldrin-templates

## Overview

Now that all frameworks use identical daisyUI classes, add a Svelte template to the CLI scaffolding.

## Dependencies

Phase 6 (templates updated).

## Steps

### 7.1 Create Svelte template
Create `eldrin-templates/templates/cloudflare-svelte-sqlite/` based on svelte-todo.

### 7.2 Enable Svelte in CLI prompts
Update `eldrin-templates/src/prompts.ts` to add Svelte option.

### 7.3 Test scaffolding

## Test Gate

```bash
cd eldrin-templates && npm run build
npx create-eldrin-project test-svelte
cd test-svelte && npm install && npm run build && npm run dev
```

## Finalize

- [ ] Manual validation: scaffold Svelte project, verify build + dev + single-spa mounting
- [ ] Commit: `feat: add Svelte template to eldrin-templates`
