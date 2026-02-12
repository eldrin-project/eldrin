# Phase 6: Update eldrin-templates

## Overview

Propagate the daisyUI changes to the template scaffolding in `eldrin-templates`.

## Dependencies

Phases 2-5 (all todo apps migrated).

## Steps

### 6.1 Update template package.json files
Swap deps to daisyUI in `package.json.template` for each framework.

### 6.2 Replace UI components in templates
Replace `src/components/ui/` with daisyUI class usage.

### 6.3 Remove shadcn config
Delete `components.json` from templates.

### 6.4 Add shared daisyUI theme
Copy `shared/eldrin-daisyui-theme.css` into each template.

### 6.5 Test scaffolding

## Test Gate

```bash
cd eldrin-templates && npm run build
npx create-eldrin-project test-app
```

## Finalize

- [ ] Manual validation: scaffold test project with each framework
- [ ] Commit: `feat: update eldrin-templates to use daisyUI 5`
