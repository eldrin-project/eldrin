import { defineConfig } from 'vite';
import type { Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { cloudflare } from '@cloudflare/vite-plugin';
import path from 'path';

/**
 * Dev-only plugin: map built filenames to source for shell integration.
 *
 * The manifest declares "entry": "/eldrin-email.js" which only exists
 * after `vite build`. During dev, redirect to the source entry so the shell
 * can dynamically import the single-spa lifecycle from the dev server.
 *
 * For CSS: the shell entry does NOT import index.css (to prevent Vite HMR
 * from injecting unscoped CSS into the shell). Instead, the shell fetches
 * this endpoint and applies @scope wrapping via its loadAppStyles() pipeline.
 * We use Vite's transformRequest to get the fully processed CSS (Tailwind, etc).
 */
function devShellCompat(): Plugin {
  return {
    name: 'dev-shell-compat',
    apply: 'serve',
    transform(code, id) {
      // Strip CSS import in dev mode to prevent Vite HMR
      // from injecting unscoped CSS into the parent shell.
      if (id.endsWith('/src/eldrin-email.tsx')) {
        return code.replace(/import\s+['"]\.\/index\.css['"];?\n?/, '');
      }
    },
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (req.url === '/eldrin-email.js') {
          req.url = '/src/eldrin-email.tsx';
          return next();
        }
        if (req.url === '/eldrin-email.css') {
          try {
            const result = await server.transformRequest('/src/index.css');
            let css = '';
            if (result?.code) {
              const match = result.code.match(
                /const __vite__css\s*=\s*"([\s\S]*?)"\n/,
              );
              if (match) {
                css = match[1]
                  .replace(/\\n/g, '\n')
                  .replace(/\\t/g, '\t')
                  .replace(/\\"/g, '"')
                  .replace(/\\\\/g, '\\');
              }
            }
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.writeHead(200, { 'Content-Type': 'text/css' });
            res.end(css);
          } catch (e) {
            console.warn('[devShellCompat] CSS transform failed:', e);
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.writeHead(200, { 'Content-Type': 'text/css' });
            res.end('/* dev mode: CSS transform failed */');
          }
          return;
        }
        next();
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), cloudflare(), tailwindcss(), devShellCompat()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      'drizzle-orm/d1': path.resolve(
        __dirname,
        'node_modules/drizzle-orm/d1/index.js',
      ),
      // Shim Node.js-only module from eldrin-app-core file: dep
      'better-sqlite3': path.resolve(__dirname, 'shims/better-sqlite3.js'),
    },
  },
  server: {
    port: 4010,
    strictPort: true,
    cors: true,
  },
  build: {
    target: 'esnext',
    minify: true,
    lib: {
      entry: './src/eldrin-email.tsx',
      name: 'eldrinEmail',
      formats: ['es'],
      fileName: 'eldrin-email',
    },
  },
});
