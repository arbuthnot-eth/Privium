import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { singleFileCompression } from "vite-plugin-singlefile-compression";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), singleFileCompression()],
  build: {
    target: 'es2020', // Ensure modern ES features are preserved
    rollupOptions: {
      output: {
        format: 'es', // Explicitly set output format to ES modules
      },
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