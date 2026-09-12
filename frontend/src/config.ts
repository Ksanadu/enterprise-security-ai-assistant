/**
 * Runtime configuration.
 *
 * Only variables prefixed with `VITE_` reach the browser bundle, so nothing
 * secret may ever live here. The API base URL is empty by default, which means
 * "same origin" - in development Vite proxies `/api` to the backend.
 */
export interface AppConfig {
  readonly apiBaseUrl: string
  readonly appTitle: string
}

function readEnv(key: string, fallback: string): string {
  const value = import.meta.env[key as keyof ImportMetaEnv]
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : fallback
}

export const config: AppConfig = {
  apiBaseUrl: readEnv('VITE_API_BASE_URL', '').replace(/\/+$/, ''),
  appTitle: readEnv('VITE_APP_TITLE', 'Enterprise Security AI Assistant'),
}

export const API_PREFIX = '/api/v1'
