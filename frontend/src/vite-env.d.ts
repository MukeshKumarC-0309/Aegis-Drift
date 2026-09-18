/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Override the API origin. Empty in dev (the Vite proxy handles it) and in
   *  production when the API serves the built SPA from the same origin. */
  readonly VITE_API_BASE_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
