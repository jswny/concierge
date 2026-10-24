import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync, verify } from "node:crypto";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createTestHarness, unstable_readConfig } from "wrangler";
import { JPEG_BASE64 } from "./fixtures/jpeg.mjs";

test("Vite preserves the production configuration without enabling local debug", () => {
	// Match JSON output serialization, which omits undefined optional fields.
	const input = JSON.parse(JSON.stringify(unstable_readConfig({ config: "wrangler.jsonc" }, { redirect: false })));
	const output = JSON.parse(readFileSync(new URL("../dist/concierge/wrangler.json", import.meta.url), "utf8"));

	for (const key of [
		"name", "account_id", "compatibility_date", "compatibility_flags",
		"routes", "workers_dev", "preview_urls", "triggers",
		"kv_namespaces", "browser", "worker_loaders", "durable_objects",
		"migrations", "secrets", "observability", "upload_source_maps", "services",
	]) {
		assert.deepEqual(output[key], input[key], key);
	}

	assert.deepEqual(output.vars, input.vars);
	const { directory: inputAssetDirectory, ...inputAssets } = input.assets;
	const { directory: outputAssetDirectory, ...outputAssets } = output.assets;
	assert.deepEqual(outputAssets, inputAssets);

	for (const extension of ["svg", "png"]) {
		assert.deepEqual(readFileSync(new URL(`${outputAssetDirectory}/assets/concierge.${extension}`, new URL("../dist/concierge/", import.meta.url))),
			readFileSync(new URL(`${inputAssetDirectory}/assets/concierge.${extension}`, new URL("../", import.meta.url))));
	}

	assert.notEqual(output.vars.CONCIERGE_DEBUG, "true");
	assert.equal(output.main, "index.js");
	assert.equal(output.no_bundle, true);
	assert.ok(!output.secrets.required.includes("NOTION_TOKEN"));
});

test("the Vite bundle runs MCP through the existing Durable Object and Worker Loader", async () => {
	const output = JSON.parse(readFileSync(new URL("../dist/concierge/wrangler.json", import.meta.url), "utf8"));
	const kalshiKeys = generateKeyPairSync("ed25519");

	const harness = createTestHarness({
		root: fileURLToPath(new URL("..", import.meta.url)),
		workers: [
			{
				configPath: "./dist/concierge/wrangler.json",
				bindingOverrides: { BROWSER: "browser-mock" },
				vars: { CONCIERGE_DEBUG: "true" },
				secrets: {
					...Object.fromEntries(output.secrets.required.map((name) => [name, "unused-build-test-secret"])),
					TWILIO_ACCOUNT_SID: `AC${"a".repeat(32)}`,
					TWILIO_API_KEY_SID: `SK${"b".repeat(32)}`,
					TWILIO_API_KEY_SECRET: "build-twilio-secret",
					TWILIO_WEBHOOK_KEY_ID: `webhooks_sharedkey_${"a".repeat(26)}`,
					KALSHI_API_KEY_ID: "build-kalshi-key-id",
					KALSHI_PRIVATE_KEY: kalshiKeys.privateKey.export({ format: "pem", type: "pkcs8" }),
				},
			},
			{
				config: { name: "browser-mock", main: "./tests/fixtures/browser-worker.mjs", compatibility_date: "2026-07-15" },
			},
		],
	});

	const client = new Client({ name: "concierge-build-test", version: "1" }, {
		versionNegotiation: { mode: { pin: "2026-07-28" } },
	});

	const originalFetch = globalThis.fetch;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);
		const url = new URL(request.url);

		if (url.hostname === "external-api.kalshi.com") {
			assert.equal(request.headers.get("KALSHI-ACCESS-KEY"), "build-kalshi-key-id");
			assert.equal(request.method, "GET");
			assert.equal(url.pathname, "/trade-api/v2/portfolio/balance");
			const message = request.headers.get("KALSHI-ACCESS-TIMESTAMP") + request.method + url.pathname;
			assert.ok(verify(null, Buffer.from(message), kalshiKeys.publicKey, Buffer.from(request.headers.get("KALSHI-ACCESS-SIGNATURE"), "base64")));

			return Response.json({ balance: 12345, portfolio_value: 5678, updated_ts: 1234567890 });
		}

		if (url.hostname === "api.twilio.com") {
			assert.equal(request.headers.get("Authorization"), `Basic ${Buffer.from(`SK${"b".repeat(32)}:build-twilio-secret`).toString("base64")}`);
			assert.equal(url.pathname, `/2010-04-01/Accounts/AC${"a".repeat(32)}/Messages.json`);

			return Response.json({ messages: [{ sid: "SMbuild", status: "received" }], next_page_uri: null });
		}

		if (url.hostname === "api.exa.ai") {
			assert.equal(request.headers.get("Authorization"), "Bearer unused-build-test-secret");
			assert.equal(url.pathname, "/search");
			assert.deepEqual(await request.json(), { query: "fixture", numResults: 1 });

			return Response.json({ requestId: "exa-build", results: [{ url: "https://example.com", title: "Example" }] });
		}

		if (url.hostname === "api.fantasypros.com") {
			assert.equal(request.headers.get("x-api-key"), "unused-build-test-secret");
			assert.equal(request.method, "GET");

			if (url.pathname === "/public/v2/json/nfl/private-build-error-marker") {
				return Response.json({ message: "private-build-response-marker" }, { status: 403 });
			}

			assert.equal(url.pathname, "/public/v2/json/nfl/2026/consensus-rankings");
			assert.equal(url.searchParams.get("position"), "RB");

			return Response.json({ players: [{ player_id: 9001, rank_ecr: 1 }], scoring: "PPR" });
		}

		if (url.hostname !== "api.ui.com") return originalFetch(input, init);

		return new Response(Buffer.from(JPEG_BASE64, "base64"), { headers: { "Content-Type": "image/jpeg" } });
	};

	try {
		const listener = await harness.listen();
		const worker = harness.getWorker("concierge");
		const logo = await harness.fetch("/assets/concierge.svg");
		assert.equal(logo.status, 200);
		assert.match(logo.headers.get("Content-Type"), /^image\/svg\+xml/);
		assert.equal(await logo.text(), readFileSync(new URL("../public/assets/concierge.svg", import.meta.url), "utf8"));
		const png = await harness.fetch("/assets/concierge.png");
		assert.equal(png.status, 200);
		assert.match(png.headers.get("Content-Type"), /^image\/png/);
		assert.deepEqual(Buffer.from(await png.arrayBuffer()), readFileSync(new URL("../public/assets/concierge.png", import.meta.url)));
		const protectedResponse = await worker.fetch("https://concierge.j1.io/mcp", { method: "POST" });
		assert.equal(protectedResponse.status, 401);
		await client.connect(new StreamableHTTPClientTransport(new URL("/debug/mcp", listener.url), {
			fetch: (input, init) => worker.fetch(input, init),
		}));
		assert.equal(client.getNegotiatedProtocolVersion(), "2026-07-28");

		// The stock SDK client strips draft capability keys; check the wire response.
		const eventDiscovery = await worker.fetch(new URL("/debug/mcp", listener.url), {
			method: "POST",
			headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "server/discover" },
			body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: {
				"io.modelcontextprotocol/protocolVersion": "2026-07-28",
				"io.modelcontextprotocol/clientInfo": { name: "event-build-test", version: "1" },
				"io.modelcontextprotocol/clientCapabilities": {},
			} } }),
		});

		assert.deepEqual((await eventDiscovery.json()).result.capabilities.events, { listChanged: false });
		const tools = (await client.listTools()).tools;
		assert.deepEqual(tools.map((tool) => tool.name), ["code"]);
		assert.equal(tools[0].icons, undefined);
		assert.deepEqual(client.getServerVersion().icons, [
			{ src: "https://concierge.j1.io/assets/concierge.png", mimeType: "image/png", sizes: ["256x256"] },
			{ src: "https://concierge.j1.io/assets/concierge.svg", mimeType: "image/svg+xml", sizes: ["any"] },
		]);
		assert.match(tools[0].description, /- `maps`.*Routes API/);
		assert.match(tools[0].description, /- `google`.*Gmail.*Google Calendar/);
		assert.match(tools[0].description, /- `unifi`.*unifi\.request/);
		assert.match(tools[0].description, /- `twilio`.*twilio\.request/);
		assert.match(tools[0].description, /- `exa`.*exa\.request/);
		assert.match(tools[0].description, /- `kalshi`.*kalshi\.request/);
		assert.match(tools[0].description, /- `fantasypros`.*fantasypros\.request/);
		assert.doesNotMatch(tools[0].description, /notion/i);
		assert.match(tools[0].description, /search for `maps directions`/);

		const result = await client.callTool({ name: "code", arguments: {
			code: "async () => ({ sum: 2 + 2, matches: await codemode.search('request') })",
		} });

		assert.equal(result.isError, undefined);
		assert.equal(result.structuredContent.result.sum, 4);
		assert.deepEqual(result.structuredContent.result.matches.results.map((match) => match.path).sort(), ["cloudflare.read_webpage_as_markdown", "exa.request", "fantasypros.request", "google.request", "kalshi.request", "maps.request", "twilio.request", "unifi.request"]);

		const page = await client.callTool({ name: "code", arguments: {
			code: "async () => await cloudflare.read_webpage_as_markdown({ url: 'https://example.com/test' })",
		} });

		assert.equal(page.isError, undefined);
		assert.equal(page.structuredContent.result.status, 200);
		assert.equal(page.structuredContent.result.finalUrl, "https://example.com/final");
		assert.match(page.structuredContent.result.markdown, /Wait: networkidle2/);

		const image = await client.callTool({ name: "code", arguments: {
			code: "async () => ({ snapshot: await unifi.request({ method: 'GET', path: '/v1/connector/consoles/id/proxy/protect/integration/v1/cameras/camera-id/snapshot' }) })",
		} });

		assert.equal(image.isError, undefined);
		assert.deepEqual(image.content[1], { type: "image", mimeType: "image/jpeg", data: JPEG_BASE64 });
		assert.deepEqual(image.structuredContent.result.snapshot, {
			type: "image", mimeType: "image/jpeg", byteLength: Buffer.from(JPEG_BASE64, "base64").length, contentIndex: 1,
		});
		assert.deepEqual(JSON.parse(image.content[0].text), image.structuredContent.result);

		const messages = await client.callTool({ name: "code", arguments: {
			code: "async () => await twilio.request({ method: 'GET', path: '/2010-04-01/Accounts/{AccountSid}/Messages.json', query: { PageSize: 1 } })",
		} });

		assert.equal(messages.isError, undefined, JSON.stringify(messages));
		assert.deepEqual(messages.structuredContent.result, { messages: [{ sid: "SMbuild", status: "received" }], next_page_uri: null });

		const search = await client.callTool({ name: "code", arguments: {
			code: "async () => await exa.request({ method: 'POST', path: '/search', body: { query: 'fixture', numResults: 1 } })",
		} });

		assert.equal(search.isError, undefined, JSON.stringify(search));
		assert.deepEqual(search.structuredContent.result, { requestId: "exa-build", results: [{ url: "https://example.com", title: "Example" }] });

		const balance = await client.callTool({ name: "code", arguments: {
			code: "async () => await kalshi.request({ method: 'GET', path: '/trade-api/v2/portfolio/balance' })",
		} });

		assert.equal(balance.isError, undefined, JSON.stringify(balance));
		assert.deepEqual(balance.structuredContent.result, { balance: 12345, portfolio_value: 5678, updated_ts: 1234567890 });

		const rankings = await client.callTool({ name: "code", arguments: {
			code: "async () => await fantasypros.request({ method: 'GET', path: '/public/v2/json/nfl/2026/consensus-rankings', query: { position: 'RB', scoring: 'PPR' } })",
		} });

		assert.equal(rankings.isError, undefined, JSON.stringify(rankings));
		assert.deepEqual(rankings.structuredContent.result, { players: [{ player_id: 9001, rank_ecr: 1 }], scoring: "PPR" });

		const failed = await client.callTool({ name: "code", arguments: {
			code: "async () => await fantasypros.request({ method: 'GET', path: '/public/v2/json/nfl/private-build-error-marker', query: { filter: 'private-build-query-marker' } })",
		} });

		assert.equal(failed.isError, true);
		assert.match(failed.content[0].text, /GET \/public\/v2\/json\/nfl\/private-build-error-marker: FantasyPros request: API returned HTTP 403/);
		assert.doesNotMatch(failed.content[0].text, /private-build-query-marker|private-build-response-marker/);
		const logs = harness.getLogs();
		assert.ok(logs.some((log) => String(log.message).includes("codemode: fantasypros.request failed")));
		assert.doesNotMatch(JSON.stringify(logs), /private-build-error-marker|private-build-query-marker|private-build-response-marker|unused-build-test-secret/);
	} finally {
		globalThis.fetch = originalFetch;
		await client.close();
		await harness.close();
	}
});
