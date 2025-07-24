/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_PRIVY_APP_ID: string
  // Add other environment variables here as needed
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}