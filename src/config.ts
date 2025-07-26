// Centralized configuration for the MCP server
const SERVER_CONFIG = {
  NAME: "Privium",
  VERSION: "0.99.21"
} as const

// Export individual constants for convenience
export const SERVER_NAME = SERVER_CONFIG.NAME
export const SERVER_VERSION = SERVER_CONFIG.VERSION