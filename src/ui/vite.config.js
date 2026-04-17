import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'

export default defineConfig({
  plugins: [vue()],
  root: path.resolve(__dirname, '../..'),
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true
      },
      '/config': {
        target: 'http://localhost:8080',
        changeOrigin: true
      },
      '/ui': {
        target: 'http://localhost:8080',
        changeOrigin: true
      }
    }
  },
  build: {
    outDir: 'dist-ui',
    emptyOutDir: true
  }
})