import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    port: 5173,
    proxy: {
      // Dev only. In the container, nginx proxies /api to the server instead;
      // keeping the paths identical means no code branches on the environment.
      // The target is overridable so the e2e suite can point the proxy at a
      // throwaway backend on an ephemeral port (see e2e/global-setup.ts).
      '/api': {
        target: process.env.VITE_API_PROXY_TARGET ?? 'http://127.0.0.1:18233',
        changeOrigin: true,
      },
    },
  },
  build: {
    // No source maps in production: a bundle for a secrets vault should not
    // ship a readable copy of its own source to a CDN or a browser cache.
    sourcemap: false,
  },
})
