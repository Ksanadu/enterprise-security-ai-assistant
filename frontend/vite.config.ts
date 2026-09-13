import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv, type Plugin } from 'vite'

/**
 * Inject a Content-Security-Policy into the built `index.html`.
 *
 * It is added here rather than written into the template because the Vite dev
 * server injects an inline module script for hot reload, which a production
 * policy must refuse. Injecting at build time keeps development working and
 * ships a strict policy to users.
 */
function contentSecurityPolicy(): Plugin {
  const policy = [
    "default-src 'self'",
    "script-src 'self'",
    // Vite injects a small inline <style> block; styles cannot execute script.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    // The SPA only ever calls its own origin (the API is proxied or same-origin).
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join('; ')

  return {
    name: 'esaa-content-security-policy',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace(
        '<meta name="referrer" content="no-referrer" />',
        `<meta name="referrer" content="no-referrer" />\n    <meta http-equiv="Content-Security-Policy" content="${policy}" />`,
      )
    },
  }
}

/**
 * Vite configuration.
 *
 * The backend URL is read from the environment (`VITE_API_BASE_URL`) so no host
 * or port is hardcoded. In development the dev server proxies `/api` to the
 * backend, which also avoids CORS during local work.
 */
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_')
  const backendTarget = env.VITE_DEV_PROXY_TARGET || 'http://127.0.0.1:8000'
  const port = Number(env.VITE_DEV_PORT || 5173)

  return {
    plugins: [react(), contentSecurityPolicy()],
    server: {
      host: '127.0.0.1',
      port,
      strictPort: true,
      proxy: {
        '/api': {
          target: backendTarget,
          changeOrigin: true,
        },
      },
    },
    preview: {
      host: '127.0.0.1',
      port: Number(env.VITE_PREVIEW_PORT || 4173),
      // Mirrors the deployed topology: nginx serves the built files and proxies
      // /api to the backend. `vite preview` does not inherit `server.proxy`, so
      // without this the production bundle (and its Content-Security-Policy)
      // could not be exercised locally without a container.
      proxy: {
        '/api': {
          target: backendTarget,
          changeOrigin: true,
        },
      },
    },
    build: {
      outDir: 'dist',
      sourcemap: mode !== 'production',
    },
    test: {
      environment: 'jsdom',
      globals: true,
      setupFiles: ['./src/test/setup.ts'],
      css: false,
      include: ['src/**/*.{test,spec}.{ts,tsx}'],
      coverage: {
        provider: 'v8',
        reporter: ['text', 'html'],
        include: ['src/**/*.{ts,tsx}'],
        exclude: ['src/**/*.test.{ts,tsx}', 'src/test/**', 'src/vite-env.d.ts'],
        // Measured before these were set: 91% statements, 80% branches, 74%
        // functions. They exist because "59 tests pass" was previously the whole
        // story - a component that `App` never mounts is a component nothing
        // measures, and that is exactly how a value-blind assertion survived: the
        // suite asserted that a label rendered, never what number it carried.
        thresholds: {
          statements: 85,
          branches: 75,
          functions: 70,
          lines: 85,
        },
      },
    },
  }
})
