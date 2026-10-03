import { cloudflare } from "@cloudflare/vite-plugin";
import { defineConfig } from "vite";

export default defineConfig(({ command, isPreview }) => ({
	plugins: [
		cloudflare({
			configPath: "./wrangler.jsonc",
			// The authless MCP route is enabled only in the development server.
			config: command === "serve" && !isPreview ? { vars: { CONCIERGE_DEBUG: "true" } } : undefined,
		}),
	],
	server: { port: 8788, host: "127.0.0.1" },
	preview: { port: 8788, host: "127.0.0.1" },
	build: { sourcemap: true },
}));
