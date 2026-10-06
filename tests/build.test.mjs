import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createTestHarness, unstable_readConfig } from "wrangler";

test("Vite preserves the production configuration without enabling local debug", () => {
	// Match JSON output serialization, which omits undefined optional fields.
	const input = JSON.parse(JSON.stringify(unstable_readConfig({ config: "wrangler.jsonc" }, { redirect: false })));
	const output = JSON.parse(readFileSync(new URL("../dist/concierge/wrangler.json", import.meta.url), "utf8"));
	for (const key of [
		"name", "account_id", "compatibility_date", "compatibility_flags",
		"routes", "workers_dev", "preview_urls", "assets", "triggers",
		"kv_namespaces", "browser", "worker_loaders", "durable_objects",
		"migrations", "secrets", "observability", "upload_source_maps", "services",
	]) {
		assert.deepEqual(output[key], input[key], key);
	}
	assert.deepEqual(output.vars, input.vars);
	assert.notEqual(output.vars.CONCIERGE_DEBUG, "true");
	assert.equal(output.main, "index.js");
	assert.equal(output.no_bundle, true);
});

test("the Vite bundle runs MCP through the existing Durable Object and Worker Loader", async () => {
	const output = JSON.parse(readFileSync(new URL("../dist/concierge/wrangler.json", import.meta.url), "utf8"));
	const harness = createTestHarness({
		root: fileURLToPath(new URL("..", import.meta.url)),
		workers: [
			{
				configPath: "./dist/concierge/wrangler.json",
				bindingOverrides: { BROWSER: "browser-mock" },
				vars: { CONCIERGE_DEBUG: "true" },
				secrets: Object.fromEntries(output.secrets.required.map((name) => [name, "unused-build-test-secret"])),
			},
			{
				config: { name: "browser-mock", main: "./tests/fixtures/browser-worker.mjs", compatibility_date: "2026-07-15" },
			},
		],
	});
	const client = new Client({ name: "concierge-build-test", version: "1" }, {
		versionNegotiation: { mode: { pin: "2026-07-28" } },
	});
	try {
		const listener = await harness.listen();
		const worker = harness.getWorker("concierge");
		const protectedResponse = await worker.fetch("https://concierge.j1.io/mcp", { method: "POST" });
		assert.equal(protectedResponse.status, 401);
		await client.connect(new StreamableHTTPClientTransport(new URL("/debug/mcp", listener.url), {
			fetch: (input, init) => worker.fetch(input, init),
		}));
		assert.equal(client.getNegotiatedProtocolVersion(), "2026-07-28");
		const tools = (await client.listTools()).tools;
		assert.deepEqual(tools.map((tool) => tool.name), ["code"]);
		assert.match(tools[0].description, /- `maps`.*Routes API/);
		assert.match(tools[0].description, /- `google`.*Gmail/);
		assert.match(tools[0].description, /search for `maps directions`/);
		const result = await client.callTool({ name: "code", arguments: {
			code: "async () => ({ sum: 2 + 2, matches: await codemode.search('request') })",
		} });
		assert.equal(result.isError, undefined);
		assert.equal(result.structuredContent.result.sum, 4);
		assert.deepEqual(result.structuredContent.result.matches.results.map((match) => match.path).sort(), ["cloudflare.read_webpage_as_markdown", "google.request", "maps.request", "notion.request"]);
		const page = await client.callTool({ name: "code", arguments: {
			code: "async () => await cloudflare.read_webpage_as_markdown({ url: 'https://example.com/test' })",
		} });
		assert.equal(page.isError, undefined);
		assert.equal(page.structuredContent.result.status, 200);
		assert.equal(page.structuredContent.result.finalUrl, "https://example.com/final");
		assert.match(page.structuredContent.result.markdown, /Wait: networkidle2/);
	} finally {
		await client.close();
		await harness.close();
	}
});
