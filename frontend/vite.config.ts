import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { singleFileCompression } from "vite-plugin-singlefile-compression";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), singleFileCompression()],
})