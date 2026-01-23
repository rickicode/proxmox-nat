import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	// Consult https://kit.svelte.dev/docs/integrations#preprocessors
	// for more information about preprocessors
	preprocess: vitePreprocess(),

	kit: {
		// adapter-static for SPA mode (Single Page Application)
		// fallback: 'index.html' allows the Go backend to serve this file for all 404s
		adapter: adapter({
			fallback: 'index.html'
		}),
		paths: {
			base: ''
		}
	}
};

export default config;
