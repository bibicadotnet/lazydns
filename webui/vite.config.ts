import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
    plugins: [svelte()],
    server: {
        host: '0.0.0.0',
        port: 5173,
        proxy: {
            '/api': {
                target: 'http://127.0.0.1:8080',
                changeOrigin: true
            }
        }
    },
    build: {
        chunkSizeWarningLimit: 1500,
        outDir: 'dist',
        emptyOutDir: true,
        rollupOptions: {
            output: {
                manualChunks: {
                    // Separate vendor libraries into their own chunks
                    'vendor-core': ['svelte', 'svelte/animate', 'svelte/transition', 'svelte/easing'],
                    'vendor-charts': ['echarts'],
                    'vendor-router': ['svelte-spa-router']
                }
            }
        }
    }
})
