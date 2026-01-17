# Centralized Permission Middleware Design

## Problem Statement

Currently, the `react-todo` worker (and other Eldrin apps) checks permissions manually at each endpoint:

```typescript
// Current approach - repetitive in every handler
const auth = await checkPermission(request, env, 'todos', 'read');
if (auth instanceof Response) return auth;
```

This leads to:
- Repetitive code in every endpoint
- Easy to forget permission checks
- Permission logic scattered across handlers
- No centralized view of route permissions

## Proposed Solution

Create a **Permission Middleware** in `@eldrin-project/eldrin-app-core` that:

1. Loads route permissions from the app's `eldrin-app.manifest.json`
2. Intercepts requests before the main handler
3. Extracts permissions from JWT token
4. Matches the request to manifest-defined routes
5. Accepts/rejects based on permission requirements
6. Passes auth context to handlers only if authorized

## Manifest-Driven Permissions

The middleware reads route permissions from the app manifest's `api` section:

```json
{
  "api": {
    "defaultPolicy": "deny",
    "publicRoutes": ["/health"],
    "routes": [
      { "method": "GET", "path": "/todos", "permission": "todos:read" },
      { "method": "POST", "path": "/todos", "permission": "todos:create" },
      { "method": "GET", "path": "/todos/*", "permission": "todos:read" },
      { "method": ["PUT", "PATCH"], "path": "/todos/*", "permission": "todos:update" },
      { "method": "DELETE", "path": "/todos/*", "permission": "todos:delete" }
    ]
  }
}
```

**Key features:**
- `defaultPolicy`: "deny" (require auth) or "allow" (public by default)
- `publicRoutes`: Array of paths that don't require authentication
- `routes`: Route-to-permission mapping with wildcard support (`*`)
- `method`: Single method or array of methods

## Architecture

### New Module: `src/middleware/`

```
eldrin-app-core/
└── src/
    ├── auth/          # Existing - JWT verification, permission helpers
    ├── middleware/    # NEW - Request middleware
    │   ├── index.ts   # createPermissionMiddleware factory
    │   ├── types.ts   # Type definitions
    │   └── matcher.ts # Route matching logic
    └── index.ts       # Export new middleware
```

## Type Definitions

```typescript
// src/middleware/types.ts

import type { AppAuthContext } from '../auth';

/**
 * Route definition from manifest
 */
export interface ManifestRoute {
  /** HTTP method(s) - single or array */
  method: string | string[];
  /** Path pattern (supports * wildcard) */
  path: string;
  /** Required permission in "resource:action" format, or null for public */
  permission: string | null;
}

/**
 * API configuration from manifest
 */
export interface ManifestApi {
  /** Default policy for unmatched routes: "deny" requires auth, "allow" is public */
  defaultPolicy: 'deny' | 'allow';
  /** Routes that don't require authentication */
  publicRoutes?: string[];
  /** Route permission definitions */
  routes: ManifestRoute[];
}

/**
 * Minimal manifest structure needed by middleware
 */
export interface ManifestForMiddleware {
  id: string;
  developer_id?: string;
  api?: ManifestApi;
}

/**
 * CORS configuration
 */
export interface CorsConfig {
  allowOrigin: string;
  allowMethods: string;
  allowHeaders: string;
}

/**
 * Middleware configuration
 */
export interface MiddlewareConfig<TEnv = unknown> {
  /** App manifest (contains route permissions) */
  manifest: ManifestForMiddleware;
  /** Function to get JWT secret from environment */
  getSecret: (env: TEnv) => string;
  /** API path prefix (default: "/api") */
  apiPrefix?: string;
  /** CORS configuration (optional) */
  cors?: CorsConfig;
  /** Custom error handler (optional) */
  onError?: (error: MiddlewareError) => Response;
  /** Routes that should skip middleware entirely (e.g., static assets) */
  skipRoutes?: string[];
}

/**
 * Middleware error types
 */
export interface MiddlewareError {
  type: 'unauthorized' | 'forbidden' | 'route_not_found';
  message: string;
  permission?: string;
}

/**
 * Middleware result - either a response (rejected/handled) or auth context (authorized)
 */
export type MiddlewareResult =
  | { response: Response; auth?: never; url?: never; params?: never }
  | { response?: never; auth: AppAuthContext; url: URL; params: Record<string, string> };

/**
 * Permission middleware instance
 */
export interface PermissionMiddleware<TEnv = unknown> {
  handle(request: Request, env: TEnv): Promise<MiddlewareResult>;
}

/**
 * Compiled route for efficient matching
 */
export interface CompiledRoute {
  methods: Set<string>;
  pattern: RegExp;
  paramNames: string[];
  permission: { resource: string; action: string } | null;
  originalPath: string;
}
```

## Route Matching Implementation

```typescript
// src/middleware/matcher.ts

import type { ManifestRoute, CompiledRoute } from './types';

/**
 * Compile manifest routes into efficient matchers
 */
export function compileRoutes(routes: ManifestRoute[], apiPrefix: string): CompiledRoute[] {
  return routes.map((route) => {
    const methods = new Set(
      Array.isArray(route.method)
        ? route.method.map((m) => m.toUpperCase())
        : [route.method.toUpperCase()]
    );

    // Convert path pattern to regex
    // "/todos/*" -> /^\/api\/todos\/[^/]+$/
    // "/todos" -> /^\/api\/todos$/
    const fullPath = `${apiPrefix}${route.path}`;
    const paramNames: string[] = [];

    let regexPattern = fullPath
      // Escape special regex chars except * and :
      .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
      // Convert :param to named capture group
      .replace(/:([a-zA-Z_][a-zA-Z0-9_]*)/g, (_, name) => {
        paramNames.push(name);
        return '([^/]+)';
      })
      // Convert * wildcard to match segment
      .replace(/\*/g, '[^/]+');

    const pattern = new RegExp(`^${regexPattern}$`);

    // Parse permission
    let permission: { resource: string; action: string } | null = null;
    if (route.permission) {
      const [resource, action] = route.permission.split(':');
      permission = { resource, action };
    }

    return {
      methods,
      pattern,
      paramNames,
      permission,
      originalPath: route.path,
    };
  });
}

/**
 * Match a request against compiled routes
 */
export function matchRoute(
  method: string,
  pathname: string,
  compiledRoutes: CompiledRoute[]
): { route: CompiledRoute; params: Record<string, string> } | null {
  for (const route of compiledRoutes) {
    // Check method
    if (!route.methods.has(method)) continue;

    // Check path pattern
    const match = pathname.match(route.pattern);
    if (match) {
      // Extract params
      const params: Record<string, string> = {};
      route.paramNames.forEach((name, index) => {
        params[name] = match[index + 1];
      });
      return { route, params };
    }
  }

  return null;
}

/**
 * Check if path matches a public route pattern
 */
export function isPublicRoute(pathname: string, publicRoutes: string[], apiPrefix: string): boolean {
  for (const publicPath of publicRoutes) {
    const fullPath = `${apiPrefix}${publicPath}`;

    // Exact match
    if (pathname === fullPath) return true;

    // Wildcard match (e.g., "/public/*")
    if (publicPath.endsWith('/*')) {
      const prefix = `${apiPrefix}${publicPath.slice(0, -2)}`;
      if (pathname.startsWith(prefix)) return true;
    }
  }

  return false;
}
```

## Main Middleware Implementation

```typescript
// src/middleware/index.ts

import {
  verifyJWT,
  hasPermission,
  isPlatformAdmin,
  type AppAuthContext,
  type JWTVerifyOptions,
} from '../auth';
import type {
  MiddlewareConfig,
  MiddlewareResult,
  PermissionMiddleware,
  MiddlewareError,
  CompiledRoute,
} from './types';
import { compileRoutes, matchRoute, isPublicRoute } from './matcher';

export function createPermissionMiddleware<TEnv = unknown>(
  config: MiddlewareConfig<TEnv>
): PermissionMiddleware<TEnv> {
  const apiPrefix = config.apiPrefix ?? '/api';
  const manifest = config.manifest;
  const api = manifest.api;

  // Pre-compile routes for efficient matching
  const compiledRoutes: CompiledRoute[] = api?.routes
    ? compileRoutes(api.routes, apiPrefix)
    : [];

  const defaultPolicy = api?.defaultPolicy ?? 'deny';
  const publicRoutes = api?.publicRoutes ?? [];

  // Empty auth context for public routes
  const emptyAuth: AppAuthContext = {
    userId: '',
    email: '',
    name: '',
    platformRoles: [],
    permissions: [],
  };

  function createCorsHeaders(): HeadersInit {
    if (!config.cors) return {};
    return {
      'Access-Control-Allow-Origin': config.cors.allowOrigin,
      'Access-Control-Allow-Methods': config.cors.allowMethods,
      'Access-Control-Allow-Headers': config.cors.allowHeaders,
    };
  }

  function withCors(response: Response): Response {
    if (!config.cors) return response;

    const newHeaders = new Headers(response.headers);
    Object.entries(createCorsHeaders()).forEach(([key, value]) => {
      newHeaders.set(key, value);
    });

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  }

  function errorResponse(error: MiddlewareError): Response {
    if (config.onError) {
      return withCors(config.onError(error));
    }

    switch (error.type) {
      case 'unauthorized':
        return withCors(
          Response.json({ error: 'Unauthorized', message: error.message }, { status: 401 })
        );
      case 'forbidden':
        return withCors(
          Response.json({
            error: 'Forbidden',
            message: error.message,
            permission: error.permission,
          }, { status: 403 })
        );
      case 'route_not_found':
        return withCors(
          Response.json({ error: 'Not Found', message: error.message }, { status: 404 })
        );
    }
  }

  async function verifyAndGetAuth(
    request: Request,
    env: TEnv
  ): Promise<AppAuthContext | Response> {
    const jwtOptions: JWTVerifyOptions = {
      secret: config.getSecret(env),
      appId: manifest.id,
      developerId: manifest.developer_id,
    };

    const result = await verifyJWT(request, jwtOptions);

    if (!result.success) {
      return errorResponse({
        type: 'unauthorized',
        message: result.error,
      });
    }

    return result.auth;
  }

  return {
    async handle(request: Request, env: TEnv): Promise<MiddlewareResult> {
      const url = new URL(request.url);
      const method = request.method;
      const pathname = url.pathname;

      // Check skip routes (e.g., static assets)
      if (config.skipRoutes) {
        for (const skipPattern of config.skipRoutes) {
          if (pathname.startsWith(skipPattern)) {
            return { auth: emptyAuth, url, params: {} };
          }
        }
      }

      // Handle CORS preflight
      if (method === 'OPTIONS') {
        return {
          response: new Response(null, {
            status: 204,
            headers: createCorsHeaders(),
          }),
        };
      }

      // Only process API routes
      if (!pathname.startsWith(apiPrefix)) {
        return { auth: emptyAuth, url, params: {} };
      }

      // Check if it's a public route
      if (isPublicRoute(pathname, publicRoutes, apiPrefix)) {
        return { auth: emptyAuth, url, params: {} };
      }

      // Match against compiled routes
      const match = matchRoute(method, pathname, compiledRoutes);

      if (!match) {
        // No matching route defined in manifest
        if (defaultPolicy === 'allow') {
          // Allow policy: let unmatched routes through without auth
          return { auth: emptyAuth, url, params: {} };
        }

        // Deny policy: require auth for unmatched routes
        const authResult = await verifyAndGetAuth(request, env);
        if (authResult instanceof Response) {
          return { response: authResult };
        }
        return { auth: authResult, url, params: {} };
      }

      // Route matched - check if public (permission: null)
      if (match.route.permission === null) {
        return { auth: emptyAuth, url, params: match.params };
      }

      // Protected route - verify JWT
      const authResult = await verifyAndGetAuth(request, env);
      if (authResult instanceof Response) {
        return { response: authResult };
      }

      const auth = authResult;

      // Platform admins bypass permission checks
      if (isPlatformAdmin(auth)) {
        return { auth, url, params: match.params };
      }

      // Check specific permission
      const { resource, action } = match.route.permission;
      if (!hasPermission(auth, resource, action)) {
        return {
          response: errorResponse({
            type: 'forbidden',
            message: `Missing permission: ${resource}:${action}`,
            permission: `${resource}:${action}`,
          }),
        };
      }

      // Authorized!
      return { auth, url, params: match.params };
    },
  };
}

// Re-export types
export type {
  ManifestRoute,
  ManifestApi,
  ManifestForMiddleware,
  CorsConfig,
  MiddlewareConfig,
  MiddlewareError,
  MiddlewareResult,
  PermissionMiddleware,
} from './types';
```

## Usage Example - Refactored react-todo

```typescript
// worker/index.ts
import {
  runMigrations,
  createEventClient,
  createPermissionMiddleware,
} from '@eldrin-project/eldrin-app-core';
import migrations from './migrations.generated';

// Import manifest (Vite can inline JSON)
import manifest from '../public/eldrin-app.manifest.json';

// Create middleware from manifest
const middleware = createPermissionMiddleware<Env>({
  manifest,
  getSecret: (env) => env.JWT_SECRET,
  cors: {
    allowOrigin: '*',
    allowMethods: 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    allowHeaders: 'Content-Type, Authorization',
  },
  skipRoutes: ['/assets/', '/static/'],
});

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Middleware handles auth + permissions based on manifest
    const result = await middleware.handle(request, env);

    if (result.response) {
      return result.response;
    }

    const { auth, url, params } = result;

    // Run migrations (unchanged)
    // ...

    // API Routes - no permission checks needed!
    if (url.pathname.startsWith('/api/')) {
      // GET /api/todos
      if (url.pathname === '/api/todos' && request.method === 'GET') {
        const todos = await fetchTodos(env.DB, url.searchParams);
        return withCors(Response.json({ todos }));
      }

      // GET /api/todos/:id - params.id available from route match
      if (url.pathname.startsWith('/api/todos/') && request.method === 'GET' && params.id) {
        const todo = await fetchTodo(env.DB, params.id);
        return withCors(Response.json({ todo }));
      }

      // POST /api/todos
      if (url.pathname === '/api/todos' && request.method === 'POST') {
        const todo = await createTodo(env.DB, await request.json(), auth.userId);
        return withCors(Response.json({ todo }, { status: 201 }));
      }

      // ... other handlers
    }

    // Static assets
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response('Not found', { status: 404 });
  },
};
```

## Enhanced Manifest Schema

Update the manifest to support more expressive route permissions:

```json
{
  "api": {
    "defaultPolicy": "deny",
    "publicRoutes": ["/health", "/version"],
    "routes": [
      { "method": "GET", "path": "/todos", "permission": "todos:read" },
      { "method": "POST", "path": "/todos", "permission": "todos:create" },
      { "method": "GET", "path": "/todos/:id", "permission": "todos:read" },
      { "method": ["PUT", "PATCH"], "path": "/todos/:id", "permission": "todos:update" },
      { "method": "DELETE", "path": "/todos/:id", "permission": "todos:delete" },
      { "method": "PATCH", "path": "/todos/:id/toggle", "permission": "todos:update" },
      { "method": "GET", "path": "/categories", "permission": "categories:read" },
      { "method": "POST", "path": "/categories", "permission": "categories:create" },
      { "method": "DELETE", "path": "/categories/:id", "permission": "categories:delete" }
    ]
  }
}
```

**Changes from current manifest:**
- Support `:param` syntax (in addition to `*` wildcard)
- Add `publicRoutes` array for cleaner public endpoint definition
- Route definitions already support `null` permission for public routes within `routes` array

## Benefits

1. **Manifest-driven** - Route permissions defined in `eldrin-app.manifest.json`, single source of truth
2. **Generic middleware** - No app-specific paths in `eldrin-app-core`
3. **Declarative** - Easy to read and audit what permissions each route requires
4. **Less code** - Remove repetitive `checkPermission()` calls from handlers
5. **Route params** - Middleware extracts URL parameters for handlers
6. **Consistent** - Same authorization logic applied uniformly
7. **Testable** - Middleware can be unit tested separately
8. **Secure by default** - `defaultPolicy: "deny"` means unknown routes require auth

## Implementation Steps

1. Add type definitions for `ManifestApi` in `src/types.ts`
2. Create `src/middleware/` directory
3. Implement `types.ts` with middleware interfaces
4. Implement `matcher.ts` with route compilation and matching
5. Implement `index.ts` with `createPermissionMiddleware()`
6. Export from main `src/index.ts`
7. Add tests for route matching and middleware behavior
8. Update `react-todo` manifest with `:param` syntax
9. Update `react-todo` worker to use the new middleware

## Migration Path

The existing `requireJWTPermission()` and other auth helpers remain available for:
- Gradual migration of existing apps
- Cases where route-level permissions aren't enough (e.g., resource ownership checks)
- Backward compatibility

Apps can mix both approaches during migration.

## Future Enhancements

1. **Resource ownership** - Add `owner` field to check if user owns the resource
2. **Rate limiting** - Add rate limit config per route
3. **Request validation** - Integrate with schema validation
4. **Audit logging** - Log permission checks for compliance
