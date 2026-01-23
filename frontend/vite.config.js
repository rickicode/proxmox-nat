import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
	plugins: [svelte()],
	resolve: {
		alias: {
			$lib: path.resolve('./src/lib'),
		},
	},
	build: {
		outDir: 'dist',
		emptyOutDir: true,
		chunkSizeWarningLimit: 1500,
		rollupOptions: {
			output: {
				manualChunks(id) {
					// Split other node_modules into vendor chunk
					if (id.includes('node_modules')) {
						return 'vendor';
					}
				}
			}
		}
	},
	server: {
		host: true,
		proxy: {
			'/api': {
				target: 'http://localhost:3051',
				changeOrigin: true
			}
		}
	}
})
