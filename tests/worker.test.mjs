import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import {
	Client,
	StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import { createTestHarness } from "wrangler";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const MODERN_PROTOCOL_VERSION = "2026-07-28";
const LEGACY_PROTOCOL_VERSION = "2025-11-25";
const TEST_SECRETS = {
	ACCESS_AUTHORIZATION_URL: "https://access.example/authorize",
	ACCESS_CLIENT_ID: "test-access-client",
	ACCESS_CLIENT_SECRET: "test-access-secret",
	ACCESS_JWKS_URL: "https://access.example/jwks",
	ACCESS_TOKEN_URL: "https://access.example/token",
	COOKIE_ENCRYPTION_KEY: "0000000000000000000000000000000000000000000000000000000000000000",
	NOTION_TOKEN: "test-notion-token",
};

const debugServer = createConciergeHarness(true);
const productionServer = createConciergeHarness(false);
let debugMcpUrl;

before(async () => {
	const debugListener = await debugServer.listen();
	debugMcpUrl = new URL("/debug/mcp", debugListener.url);
	await productionServer.listen();
});

after(async () => {
	await Promise.all([debugServer.close(), productionServer.close()]);
});

test("keeps the production MCP route behind OAuth", async () => {
	const debugResponse = await productionServer.fetch("/debug/mcp");
	assert.equal(debugResponse.status, 404);

	const mcpResponse = await productionServer.fetch("/mcp", mcpInitializeRequest());
	assert.equal(mcpResponse.status, 401);
	assert.match(mcpResponse.headers.get("WWW-Authenticate") ?? "", /resource_metadata=/);
	assert.deepEqual(await mcpResponse.json(), {
		error: "invalid_token",
		error_description: "Missing or invalid access token",
	});

	const registrationResponse = await productionServer.fetch("/register", {
		method: "POST",
	});
	assert.equal(registrationResponse.status, 404);
});

test("advertises CIMD without dynamic client registration", async () => {
	const authorizationResponse = await productionServer.fetch(
		"/.well-known/oauth-authorization-server",
	);
	assert.equal(authorizationResponse.status, 200);
	const authorizationMetadata = await authorizationResponse.json();
	assert.equal(authorizationMetadata.client_id_metadata_document_supported, true);
	assert.equal(Object.hasOwn(authorizationMetadata, "registration_endpoint"), false);

	const resourceResponse = await productionServer.fetch(
		"/.well-known/oauth-protected-resource/mcp",
	);
	assert.equal(resourceResponse.status, 200);
	const resourceMetadata = await resourceResponse.json();
	assert.match(resourceMetadata.resource, /\/mcp$/);
	assert.deepEqual(resourceMetadata.bearer_methods_supported, ["header"]);
});

test("rejects untrusted MCP Host and Origin headers", async () => {
	const badHostResponse = await debugServer.fetch(
		"http://evil.example/debug/mcp",
		mcpInitializeRequest(),
	);
	assert.equal(badHostResponse.status, 403);
	assert.match(await badHostResponse.text(), /Invalid Host/);

	const worker = debugServer.getWorker("concierge");
	const badOriginResponse = await worker.fetch(
		"http://localhost/debug/mcp",
		mcpInitializeRequest({ Origin: "https://evil.example" }),
	);
	assert.equal(badOriginResponse.status, 403);
	assert.match(await badOriginResponse.text(), /Invalid Origin/);
});

test("serves the code tool over the modern MCP protocol", async () => {
	await withMcpClient(
		{
			versionNegotiation: {
				mode: { pin: MODERN_PROTOCOL_VERSION },
			},
		},
		async (client) => {
			assert.equal(client.getNegotiatedProtocolVersion(), MODERN_PROTOCOL_VERSION);
			const { tools } = await client.listTools();
			assert.equal(tools.length, 1);
			const [tool] = tools;
			assert.equal(tool.name, "code");
			assert.match(tool.description ?? "", /codemode\.search.*connector method names/s);
			assert.deepEqual(tool.annotations, {
				destructiveHint: true,
				idempotentHint: false,
				openWorldHint: true,
				readOnlyHint: false,
			});
			assert.deepEqual(tool.outputSchema?.required, ["result"]);

			const result = await client.callTool({
				name: "code",
				arguments: {
					code: 'async () => ({ first: 1, second: "two" })',
				},
			});
			assert.deepEqual(result.structuredContent, {
				result: { first: 1, second: "two" },
			});
			assert.deepEqual(JSON.parse(result.content[0].text), {
				first: 1,
				second: "two",
			});
		},
	);
});

test("retains legacy MCP compatibility", async () => {
	await withMcpClient(undefined, async (client) => {
		assert.equal(client.getNegotiatedProtocolVersion(), LEGACY_PROTOCOL_VERSION);
		const { tools } = await client.listTools();
		assert.deepEqual(
			tools.map((tool) => tool.name),
			["code"],
		);

		const result = await client.callTool({
			name: "code",
			arguments: { code: 'async () => "legacy"' },
		});
		assert.deepEqual(result.structuredContent, { result: "legacy" });
	});
});

test("calls Browser Run through the Cloudflare connector", async () => {
	await withMcpClient(undefined, async (client) => {
		const result = await client.callTool({
			name: "code",
			arguments: {
				code: "async () => await cloudflare.read_webpage_as_markdown({ url: 'https://example.com/test' })",
			},
		});

		assert.deepEqual(result.structuredContent, {
			result: "# Mock webpage\nURL: https://example.com/test\nWait: networkidle0",
		});
	});
});

test("calls Notion with the configured API contract", async () => {
	const originalFetch = globalThis.fetch;
	let notionRequest;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);
		if (request.url.startsWith("https://api.notion.com/")) {
			notionRequest = request;
			return Response.json({ id: "test-user", object: "user" });
		}

		return originalFetch(input, init);
	};

	try {
		await withMcpClient(undefined, async (client) => {
			const result = await client.callTool({
				name: "code",
				arguments: {
					code: "async () => await notion.request({ method: 'GET', path: '/v1/users/me', query: { preview: true } })",
				},
			});

			assert.deepEqual(result.structuredContent, {
				result: { id: "test-user", object: "user" },
			});
		});

		assert.ok(notionRequest);
		assert.equal(notionRequest.method, "GET");
		assert.equal(notionRequest.url, "https://api.notion.com/v1/users/me?preview=true");
		assert.equal(notionRequest.headers.get("Authorization"), "Bearer test-notion-token");
		assert.equal(notionRequest.headers.get("Notion-Version"), "2026-03-11");
	} finally {
		globalThis.fetch = originalFetch;
	}
});

function createConciergeHarness(debugEnabled) {
	return createTestHarness({
		root: ROOT,
		workers: [
			{
				bindingOverrides: { BROWSER: "browser-mock" },
				configPath: "./wrangler.jsonc",
				secrets: TEST_SECRETS,
				vars: { CONCIERGE_DEBUG: String(debugEnabled) },
			},
			{
				config: {
					compatibility_date: "2026-07-15",
					main: "./tests/fixtures/browser-worker.mjs",
					name: "browser-mock",
				},
			},
		],
	});
}

async function withMcpClient(options, run) {
	const client = new Client(
		{ name: "concierge-integration-test", version: "1.0.0" },
		options,
	);
	const worker = debugServer.getWorker("concierge");
	const transport = new StreamableHTTPClientTransport(debugMcpUrl, {
		fetch: (input, init) => worker.fetch(input, init),
	});

	try {
		await client.connect(transport);
		return await run(client);
	} finally {
		await client.close();
	}
}

function mcpInitializeRequest(extraHeaders = {}) {
	return {
		body: JSON.stringify({
			id: 1,
			jsonrpc: "2.0",
			method: "initialize",
			params: {
				capabilities: {},
				clientInfo: { name: "concierge-integration-test", version: "1.0.0" },
				protocolVersion: LEGACY_PROTOCOL_VERSION,
			},
		}),
		headers: {
			Accept: "application/json, text/event-stream",
			"Content-Type": "application/json",
			...extraHeaders,
		},
		method: "POST",
	};
}
