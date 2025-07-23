import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { singleFileCompression } from "vite-plugin-singlefile-compression";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), singleFileCompression()],
  build: {
    rollupOptions: {
      onwarn(warning, warn) {
        // Suppress all warnings from node_modules
        if (warning.loc?.file?.includes('node_modules')) {
          return;
        }
        // Pass other warnings through
        warn(warning);
      },
    },
  },
})