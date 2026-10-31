/// <reference types="vite/client" />
interface ImportMetaEnv {
  /** Address of killchain/api, no trailing slash. Default http://localhost:8000. */
  readonly VITE_API_URL?: string
}
interface ImportMeta {
  readonly env: ImportMetaEnv
}
